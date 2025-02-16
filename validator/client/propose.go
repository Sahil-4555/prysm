package client

// Validator client proposer functions.
import (
	"context"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/prysm/v5/async"
	"github.com/prysmaticlabs/prysm/v5/beacon-chain/core/signing"
	fieldparams "github.com/prysmaticlabs/prysm/v5/config/fieldparams"
	"github.com/prysmaticlabs/prysm/v5/config/params"
	"github.com/prysmaticlabs/prysm/v5/config/proposer"
	"github.com/prysmaticlabs/prysm/v5/consensus-types/blocks"
	"github.com/prysmaticlabs/prysm/v5/consensus-types/interfaces"
	"github.com/prysmaticlabs/prysm/v5/consensus-types/primitives"
	"github.com/prysmaticlabs/prysm/v5/crypto/bls"
	"github.com/prysmaticlabs/prysm/v5/crypto/rand"
	"github.com/prysmaticlabs/prysm/v5/encoding/bytesutil"
	"github.com/prysmaticlabs/prysm/v5/monitoring/tracing/trace"
	ethpb "github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1"
	validatorpb "github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1/validator-client"
	"github.com/prysmaticlabs/prysm/v5/runtime/version"
	prysmTime "github.com/prysmaticlabs/prysm/v5/time"
	"github.com/prysmaticlabs/prysm/v5/time/slots"
	"github.com/prysmaticlabs/prysm/v5/validator/client/iface"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

const (
	domainDataErr           = "could not get domain data"
	signingRootErr          = "could not get signing root"
	signExitErr             = "could not sign voluntary exit proposal"
	failedBlockSignLocalErr = "block rejected by local protection"
)

// ProposeBlock proposes a new beacon block for a given slot. This method collects the
// previous beacon block, any pending deposits, and ETH1 data from the beacon
// chain node to construct the new block. The new block is then processed with
// the state root computation, and finally signed by the validator before being
// sent back to the beacon node for broadcasting.
func (v *validator) ProposeBlock(ctx context.Context, slot primitives.Slot, pubKey [fieldparams.BLSPubkeyLength]byte) {
	
	//If the slot is 0 (genesis slot), the function skips block proposal because the genesis block 
	// is already created.
	if slot == 0 {
		log.Debug("Assigned to genesis slot, skipping proposal")
		return
	}

	// The function starts a tracing span (validator.ProposeBlock) for monitoring and debugging. 	
	ctx, span := trace.StartSpan(ctx, "validator.ProposeBlock")
	defer span.End()

	// In a blockchain system, multiple validators might attempt to propose blocks simultaneously. 
	// The multilock ensures that only one validator with a specific role (RoleProposer) and public key
	// (pubKey) can propose a block at a time. This prevents race conditions and ensures thread safety.
	// NewMultilock creates a new multilock for the specified keys
	lock := async.NewMultilock(fmt.Sprint(iface.RoleProposer), string(pubKey[:]))
	lock.Lock()
	defer lock.Unlock()

	// It also logs the validator's public key for identification.
	fmtKey := fmt.Sprintf("%#x", pubKey[:])
	span.SetAttributes(trace.StringAttribute("validator", fmtKey))
	log := log.WithField("pubkey", fmt.Sprintf("%#x", bytesutil.Trunc(pubKey[:])))

	// the current slot number by the number of slots per epoch.
	// For example, if slot = 64 and SlotsPerEpoch = 32. This means that slot 64 belongs to epoch 2
	epoch := primitives.Epoch(slot / params.BeaconConfig().SlotsPerEpoch)

	// Generate a cryptographic signature (RANDAO reveal) for a given epoch using the RANDAO domain
	// and private key. This signature proves that the validator is actively taking part in block 
	// proposals and helps add randomness to the blockchain.
	randaoReveal, err := v.signRandaoReveal(ctx, pubKey, epoch, slot)
	if err != nil {
		log.WithError(err).Error("Failed to sign randao reveal")
		// It determines whether the validator should emit (send out) metrics related to 
		// its account and performance.
		if v.emitAccountMetrics {
			// The WithLabelValues function gets a counter metric for specific labels 
			// (e.g., status code and HTTP method). If there's an error, it panics instead 
			// of returning an error. 
			ValidatorProposeFailVec.WithLabelValues(fmtKey).Inc()
		}
		return
	}

	// Graffiti gets the graffiti from cli or file for the validator public key.
	// Graffiti is a custom message that a validator can add to a blockchain block.
	// It’s optional and used for identification, fun, or tracking.
	g, err := v.Graffiti(ctx, pubKey)
	if err != nil {
		// Graffiti is not a critical enough to fail block production and cause
		// validator to miss block reward. When failed, validator should continue
		// to produce the block.
		log.WithError(err).Warn("Could not get graffiti")
	}

	// - Requests a new block from the beacon node by passing the slot, RANDAO reveal, and graffiti.
	// - The beacon node provides the data needed to construct the new block.
	b, err := v.validatorClient.BeaconBlock(ctx, &ethpb.BlockRequest{
		Slot:         slot,
		RandaoReveal: randaoReveal,
		Graffiti:     g,
	})
	if err != nil {
		log.WithField("slot", slot).WithError(err).Error("Failed to request block from beacon node")
		if v.emitAccountMetrics {
			ValidatorProposeFailVec.WithLabelValues(fmtKey).Inc()
		}
		return
	}

	// NewBeaconBlock creates a beacon block from a protobuf beacon block.
	// - Converts the block from the beacon node into a format that can be signed.
	// - Ensures the block is in the correct format for signing.
	wb, err := blocks.NewBeaconBlock(b.Block)
	if err != nil {
		log.WithError(err).Error("Failed to wrap block")
		if v.emitAccountMetrics {
			ValidatorProposeFailVec.WithLabelValues(fmtKey).Inc()
		}
		return
	}
	
	// Sign block with proposer domain and private key.
	// Returns the signature, block signing root, and any error.
	// - The signature proves the block was created by the validator (proposer).
	sig, signingRoot, err := v.signBlock(ctx, pubKey, epoch, slot, wb)
	if err != nil {
		log.WithError(err).Error("Failed to sign block")
		if v.emitAccountMetrics {
			ValidatorProposeFailVec.WithLabelValues(fmtKey).Inc()
		}
		return
	}

	// BuildSignedBeaconBlock assembles a block.ReadOnlySignedBeaconBlock interface compatible 
	// struct from a given beacon block and the appropriate signature. This method may be used 
	// to easily create a signed beacon block.
	// - Combines the block and signature into a signed beacon block.
	// - The signed block is ready to be proposed to the network.
	blk, err := blocks.BuildSignedBeaconBlock(wb, sig)
	if err != nil {
		log.WithError(err).Error("Failed to build signed beacon block")
		return
	}

	// SlashableProposalCheck checks if a block proposal is slashable by comparing it with the
	// block proposals history for the given public key in our complete slashing protection database defined by EIP-3076.
	// If it is not, we then update the history.
	// - Checks if proposing this block would violate slashing conditions (e.g., double proposal).
	// - Prevents the validator from being penalized for malicious behavior.
	if err := v.db.SlashableProposalCheck(ctx, pubKey, blk, signingRoot, v.emitAccountMetrics, ValidatorProposeFailVec); err != nil {
		log.WithFields(
			blockLogFields(pubKey, wb, nil),
		).WithError(err).Error("Failed block slashing protection check")
		if v.emitAccountMetrics {
			ValidatorProposeFailVec.WithLabelValues(fmtKey).Inc()
		}
		return
	}

	// Declares a variable genericSignedBlock to hold the final block that will be proposed to the network.
	var genericSignedBlock *ethpb.GenericSignedBeaconBlock
	// Special handling for Deneb blocks and later version because of blob side cars.
	// - Checks if the block version is Deneb or later and if the block is not blinded.
	// - Blinded blocks are a special type of block that don’t contain all the data (used for privacy or efficiency).
	// - Blocks from Deneb onward may include blob sidecars (extra data attached to the block), so they need special handling.
	if blk.Version() >= version.Deneb && !blk.IsBlinded() {
		// - Converts the block into a protobuf format (a serialized format used for communication).
		// - Protobuf is a compact and efficient format for transmitting data over the network. 
		pb, err := blk.Proto()
		if err != nil {
			log.WithError(err).Error("Failed to get deneb block")
			return
		}
		switch blk.Version() {
		// - Calls buildGenericSignedBlockDenebWithBlobs to create a genericSignedBlock for Deneb blocks.
		// - Deneb blocks require special handling because they include additional data (blobs).
		case version.Deneb:
			genericSignedBlock, err = buildGenericSignedBlockDenebWithBlobs(pb, b)
			if err != nil {
				log.WithError(err).Error("Failed to build generic signed block")
				return
			}
		// - Calls buildGenericSignedBlockElectraWithBlobs to handle Electra-specific features
		// - Electra is a newer version and may have additional features or data.
		case version.Electra:
			genericSignedBlock, err = buildGenericSignedBlockElectraWithBlobs(pb, b)
			if err != nil {
				log.WithError(err).Error("Failed to build generic signed block")
				return
			}
		case version.Fulu:
			genericSignedBlock, err = buildGenericSignedBlockFuluWithBlobs(pb, b)
			if err != nil {
				log.WithError(err).Error("Failed to build generic signed block")
				return
			}
		default:
			log.Errorf("Unsupported block version %s", version.String(blk.Version()))
		}
	} else {
		// - For blocks that are not Deneb or later, it converts the block into a genericSignedBlock using blk.PbGenericBlock().
		// - Ensures older block versions are still processed correctly.
		genericSignedBlock, err = blk.PbGenericBlock()
		if err != nil {
			log.WithError(err).Error("Failed to create proposal request")
			if v.emitAccountMetrics {
				ValidatorProposeFailVec.WithLabelValues(fmtKey).Inc()
			}
			return
		}
	}

	// - Sends the signed block to the beacon node for broadcasting to the network.
	// - This is the final step in proposing a new block to the blockchain.
	// - beacon-chain/rpc/prysm/v1alpha1/validator/proposer.go
	blkResp, err := v.validatorClient.ProposeBeaconBlock(ctx, genericSignedBlock)
	if err != nil {
		log.WithField("slot", slot).WithError(err).Error("Failed to propose block")
		if v.emitAccountMetrics {
			ValidatorProposeFailVec.WithLabelValues(fmtKey).Inc()
		}
		return
	}

	span.SetAttributes(
		trace.StringAttribute("blockRoot", fmt.Sprintf("%#x", blkResp.BlockRoot)),
		trace.Int64Attribute("numDeposits", int64(len(blk.Block().Body().Deposits()))),
		trace.Int64Attribute("numAttestations", int64(len(blk.Block().Body().Attestations()))),
	)

	if err := logProposedBlock(log, blk, blkResp.BlockRoot); err != nil {
		log.WithError(err).Error("Failed to log proposed block")
	}

	// Tracks how many times the validator successfully proposed a block.
	if v.emitAccountMetrics {
		ValidatorProposeSuccessVec.WithLabelValues(fmtKey).Inc()
	}
}

func logProposedBlock(log *logrus.Entry, blk interfaces.SignedBeaconBlock, blkRoot []byte) error {
	if blk.Version() >= version.Bellatrix {
		p, err := blk.Block().Body().Execution()
		if err != nil {
			return errors.Wrap(err, "failed to get execution payload")
		}
		log = log.WithFields(logrus.Fields{
			"payloadHash": fmt.Sprintf("%#x", bytesutil.Trunc(p.BlockHash())),
			"parentHash":  fmt.Sprintf("%#x", bytesutil.Trunc(p.ParentHash())),
			"blockNumber": p.BlockNumber(),
		})
		if !blk.IsBlinded() {
			txs, err := p.Transactions()
			if err != nil {
				return errors.Wrap(err, "failed to get execution payload transactions")
			}
			log = log.WithField("txCount", len(txs))
		}
		if p.GasLimit() != 0 {
			log = log.WithField("gasUtilized", float64(p.GasUsed())/float64(p.GasLimit()))
		}
		if blk.Version() >= version.Capella && !blk.IsBlinded() {
			withdrawals, err := p.Withdrawals()
			if err != nil {
				return errors.Wrap(err, "failed to get execution payload withdrawals")
			}
			log = log.WithField("withdrawalCount", len(withdrawals))
		}
		if blk.Version() >= version.Deneb {
			kzgs, err := blk.Block().Body().BlobKzgCommitments()
			if err != nil {
				return errors.Wrap(err, "failed to get kzg commitments")
			} else if len(kzgs) != 0 {
				log = log.WithField("kzgCommitmentCount", len(kzgs))
			}
		}
	}

	br := fmt.Sprintf("%#x", bytesutil.Trunc(blkRoot))
	graffiti := blk.Block().Body().Graffiti()
	log.WithFields(logrus.Fields{
		"slot":             blk.Block().Slot(),
		"blockRoot":        br,
		"attestationCount": len(blk.Block().Body().Attestations()),
		"depositCount":     len(blk.Block().Body().Deposits()),
		"graffiti":         string(graffiti[:]),
		"fork":             version.String(blk.Block().Version()),
	}).Info("Submitted new block")

	return nil
}

func buildGenericSignedBlockDenebWithBlobs(pb proto.Message, b *ethpb.GenericBeaconBlock) (*ethpb.GenericSignedBeaconBlock, error) {
	denebBlock, ok := pb.(*ethpb.SignedBeaconBlockDeneb)
	if !ok {
		return nil, errors.New("could cast to deneb block")
	}
	return &ethpb.GenericSignedBeaconBlock{
		Block: &ethpb.GenericSignedBeaconBlock_Deneb{
			Deneb: &ethpb.SignedBeaconBlockContentsDeneb{
				Block:     denebBlock,
				KzgProofs: b.GetDeneb().KzgProofs,
				Blobs:     b.GetDeneb().Blobs,
			},
		},
	}, nil
}

func buildGenericSignedBlockElectraWithBlobs(pb proto.Message, b *ethpb.GenericBeaconBlock) (*ethpb.GenericSignedBeaconBlock, error) {
	electraBlock, ok := pb.(*ethpb.SignedBeaconBlockElectra)
	if !ok {
		return nil, errors.New("could cast to electra block")
	}
	return &ethpb.GenericSignedBeaconBlock{
		Block: &ethpb.GenericSignedBeaconBlock_Electra{
			Electra: &ethpb.SignedBeaconBlockContentsElectra{
				Block:     electraBlock,
				KzgProofs: b.GetElectra().KzgProofs,
				Blobs:     b.GetElectra().Blobs,
			},
		},
	}, nil
}

func buildGenericSignedBlockFuluWithBlobs(pb proto.Message, b *ethpb.GenericBeaconBlock) (*ethpb.GenericSignedBeaconBlock, error) {
	fuluBlock, ok := pb.(*ethpb.SignedBeaconBlockFulu)
	if !ok {
		return nil, errors.New("could cast to fulu block")
	}
	return &ethpb.GenericSignedBeaconBlock{
		Block: &ethpb.GenericSignedBeaconBlock_Fulu{
			Fulu: &ethpb.SignedBeaconBlockContentsFulu{
				Block:     fuluBlock,
				KzgProofs: b.GetFulu().KzgProofs,
				Blobs:     b.GetFulu().Blobs,
			},
		},
	}, nil
}

// ProposeExit performs a voluntary exit on a validator.
// The exit is signed by the validator before being sent to the beacon node for broadcasting.
func ProposeExit(
	ctx context.Context,
	validatorClient iface.ValidatorClient,
	signer iface.SigningFunc,
	pubKey []byte,
	epoch primitives.Epoch,
) error {
	ctx, span := trace.StartSpan(ctx, "validator.ProposeExit")
	defer span.End()

	signedExit, err := CreateSignedVoluntaryExit(ctx, validatorClient, signer, pubKey, epoch)
	if err != nil {
		return errors.Wrap(err, "failed to create signed voluntary exit")
	}
	exitResp, err := validatorClient.ProposeExit(ctx, signedExit)
	if err != nil {
		return errors.Wrap(err, "failed to propose voluntary exit")
	}

	span.SetAttributes(
		trace.StringAttribute("exitRoot", fmt.Sprintf("%#x", exitResp.ExitRoot)),
	)
	return nil
}

func CurrentEpoch(genesisTime *timestamp.Timestamp) (primitives.Epoch, error) {
	totalSecondsPassed := prysmTime.Now().Unix() - genesisTime.Seconds
	currentSlot := primitives.Slot((uint64(totalSecondsPassed)) / params.BeaconConfig().SecondsPerSlot)
	currentEpoch := slots.ToEpoch(currentSlot)
	return currentEpoch, nil
}

func CreateSignedVoluntaryExit(
	ctx context.Context,
	validatorClient iface.ValidatorClient,
	signer iface.SigningFunc,
	pubKey []byte,
	epoch primitives.Epoch,
) (*ethpb.SignedVoluntaryExit, error) {
	ctx, span := trace.StartSpan(ctx, "validator.CreateSignedVoluntaryExit")
	defer span.End()

	indexResponse, err := validatorClient.ValidatorIndex(ctx, &ethpb.ValidatorIndexRequest{PublicKey: pubKey})
	if err != nil {
		return nil, errors.Wrap(err, "gRPC call to get validator index failed")
	}
	exit := &ethpb.VoluntaryExit{Epoch: epoch, ValidatorIndex: indexResponse.Index}
	slot, err := slots.EpochStart(epoch)
	if err != nil {
		return nil, errors.Wrap(err, "failed to retrieve slot")
	}
	sig, err := signVoluntaryExit(ctx, validatorClient, signer, pubKey, exit, slot)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign voluntary exit")
	}

	return &ethpb.SignedVoluntaryExit{Exit: exit, Signature: sig}, nil
}

// Sign randao reveal with randao domain and private key.
func (v *validator) signRandaoReveal(ctx context.Context, pubKey [fieldparams.BLSPubkeyLength]byte, epoch primitives.Epoch, slot primitives.Slot) ([]byte, error) {
	ctx, span := trace.StartSpan(ctx, "validator.signRandaoReveal")
	defer span.End()

	// Calls domainData to fetch the domain data for the DomainRandao.
	// The domain ensures the signature is only valid for RANDAO-related operations.
	// Domains prevent signature reuse across different purposes (e.g., block proposals, attestations).
	domain, err := v.domainData(ctx, epoch, params.BeaconConfig().DomainRandao[:])
	if err != nil {
		return nil, errors.Wrap(err, domainDataErr)
	}
	if domain == nil {
		return nil, errors.New(domainDataErr)
	}

	var randaoReveal bls.Signature
	// Converts the epoch into a SSZUint64 type (a serializable format for Ethereum 2.0).
	sszUint := primitives.SSZUint64(epoch)
	// Computes the signing root by combining the epoch and the domain.
	// The signing root is the data that will be signed. Ensures the signature is unique to this epoch and domain.
	root, err := signing.ComputeSigningRoot(&sszUint, domain.SignatureDomain)
	if err != nil {
		return nil, err
	}

	// Calls the key manager (v.km.Sign) to sign the signing root using the validator’s private key.
	// The signature proves the validator is participating honestly and contributes to the blockchain’s randomness.
	randaoReveal, err = v.km.Sign(ctx, &validatorpb.SignRequest{
		PublicKey:       pubKey[:],
		SigningRoot:     root[:],
		SignatureDomain: domain.SignatureDomain,
		Object:          &validatorpb.SignRequest_Epoch{Epoch: epoch},
		SigningSlot:     slot,
	})
	if err != nil {
		return nil, err
	}
	// Converts the signature into a byte array ([]byte) for transmission or storage.
	// The marshaled signature can be sent to the beacon node for verification.
	return randaoReveal.Marshal(), nil
}

// Sign block with proposer domain and private key.
// Returns the signature, block signing root, and any error.
func (v *validator) signBlock(ctx context.Context, pubKey [fieldparams.BLSPubkeyLength]byte, epoch primitives.Epoch, slot primitives.Slot, b interfaces.ReadOnlyBeaconBlock) ([]byte, [32]byte, error) {
	ctx, span := trace.StartSpan(ctx, "validator.signBlock")
	defer span.End()
	// Calls domainData to fetch the domain data for the DomainBeaconProposer
	// Domain data in blockchain, specifically in Ethereum's beacon chain, serves as a cryptographic
	// context that ensures signatures are purpose-specific and cannot be reused across different types of actions.
	domain, err := v.domainData(ctx, epoch, params.BeaconConfig().DomainBeaconProposer[:])
	if err != nil {
		return nil, [32]byte{}, errors.Wrap(err, domainDataErr)
	}
	if domain == nil {
		return nil, [32]byte{}, errors.New(domainDataErr)
	}

	// ComputeSigningRoot computes the root of the object by calculating the hash tree root of the
	// signing data with the given domain.
	// - Computes the signing root by combining the block data and the domain.
	// - The signing root is the data that will be signed. & Ensures the signature is unique to this block and domain.
	blockRoot, err := signing.ComputeSigningRoot(b, domain.SignatureDomain)
	if err != nil {
		return nil, [32]byte{}, errors.Wrap(err, signingRootErr)
	}

	// Converts the block into a signing request object (sro).
	// This object contains the data to be signed.
	// Ensures the block is in the correct format for signing.
	sro, err := b.AsSignRequestObject()
	if err != nil {
		return nil, [32]byte{}, err
	}

	// Sign signs a message using a validator's private key.
	// The signature proves the block was created by the validator (proposer).
	sig, err := v.km.Sign(ctx, &validatorpb.SignRequest{
		PublicKey:       pubKey[:],
		SigningRoot:     blockRoot[:],
		SignatureDomain: domain.SignatureDomain,
		Object:          sro,
		SigningSlot:     slot,
	})
	if err != nil {
		return nil, [32]byte{}, errors.Wrap(err, "could not sign block proposal")
	}

	// Converts the signature into a byte array ([]byte) for transmission or storage.
	return sig.Marshal(), blockRoot, nil
}

// Sign voluntary exit with proposer domain and private key.
func signVoluntaryExit(
	ctx context.Context,
	validatorClient iface.ValidatorClient,
	signer iface.SigningFunc,
	pubKey []byte,
	exit *ethpb.VoluntaryExit,
	slot primitives.Slot,
) ([]byte, error) {
	ctx, span := trace.StartSpan(ctx, "validator.signVoluntaryExit")
	defer span.End()

	req := &ethpb.DomainRequest{
		Epoch:  exit.Epoch,
		Domain: params.BeaconConfig().DomainVoluntaryExit[:],
	}

	domain, err := validatorClient.DomainData(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, domainDataErr)
	}
	if domain == nil {
		return nil, errors.New(domainDataErr)
	}

	exitRoot, err := signing.ComputeSigningRoot(exit, domain.SignatureDomain)
	if err != nil {
		return nil, errors.Wrap(err, signingRootErr)
	}

	sig, err := signer(ctx, &validatorpb.SignRequest{
		PublicKey:       pubKey,
		SigningRoot:     exitRoot[:],
		SignatureDomain: domain.SignatureDomain,
		Object:          &validatorpb.SignRequest_Exit{Exit: exit},
		SigningSlot:     slot,
	})
	if err != nil {
		return nil, errors.Wrap(err, signExitErr)
	}
	return sig.Marshal(), nil
}

// Graffiti gets the graffiti from cli or file for the validator public key.
func (v *validator) Graffiti(ctx context.Context, pubKey [fieldparams.BLSPubkeyLength]byte) ([]byte, error) {
	ctx, span := trace.StartSpan(ctx, "validator.Graffiti")
	defer span.End()

	if v.proposerSettings != nil {
		// Check proposer settings for specific key first
		if v.proposerSettings.ProposeConfig != nil {
			option, ok := v.proposerSettings.ProposeConfig[pubKey]
			if ok && option.GraffitiConfig != nil {
				return []byte(option.GraffitiConfig.Graffiti), nil
			}
		}
		// Check proposer settings for default settings second
		if v.proposerSettings.DefaultConfig != nil {
			if v.proposerSettings.DefaultConfig.GraffitiConfig != nil {
				return []byte(v.proposerSettings.DefaultConfig.GraffitiConfig.Graffiti), nil
			}
		}
	}

	// When specified, use default graffiti from the command line.
	if len(v.graffiti) != 0 {
		return bytesutil.PadTo(v.graffiti, 32), nil
	}

	if v.graffitiStruct == nil {
		return nil, errors.New("graffitiStruct can't be nil")
	}

	// When specified, individual validator specified graffiti takes the third priority.
	idx, err := v.validatorClient.ValidatorIndex(ctx, &ethpb.ValidatorIndexRequest{PublicKey: pubKey[:]})
	if err != nil {
		return nil, err
	}
	g, ok := v.graffitiStruct.Specific[idx.Index]
	if ok {
		return bytesutil.PadTo([]byte(g), 32), nil
	}

	// When specified, a graffiti from the ordered list in the file take fourth priority.
	if v.graffitiOrderedIndex < uint64(len(v.graffitiStruct.Ordered)) {
		graffiti := v.graffitiStruct.Ordered[v.graffitiOrderedIndex]
		v.graffitiOrderedIndex = v.graffitiOrderedIndex + 1
		err := v.db.SaveGraffitiOrderedIndex(ctx, v.graffitiOrderedIndex)
		if err != nil {
			return nil, errors.Wrap(err, "failed to update graffiti ordered index")
		}
		return bytesutil.PadTo([]byte(graffiti), 32), nil
	}

	// When specified, a graffiti from the random list in the file take Fifth priority.
	if len(v.graffitiStruct.Random) != 0 {
		r := rand.NewGenerator()
		r.Seed(time.Now().Unix())
		i := r.Uint64() % uint64(len(v.graffitiStruct.Random))
		return bytesutil.PadTo([]byte(v.graffitiStruct.Random[i]), 32), nil
	}

	// Finally, default graffiti if specified in the file will be used.
	if v.graffitiStruct.Default != "" {
		return bytesutil.PadTo([]byte(v.graffitiStruct.Default), 32), nil
	}

	return []byte{}, nil
}

func (v *validator) SetGraffiti(ctx context.Context, pubkey [fieldparams.BLSPubkeyLength]byte, graffiti []byte) error {
	ctx, span := trace.StartSpan(ctx, "validator.SetGraffiti")
	defer span.End()

	if graffiti == nil {
		return nil
	}
	settings := &proposer.Settings{}
	if v.proposerSettings != nil {
		settings = v.proposerSettings.Clone()
	}
	if settings.ProposeConfig == nil {
		settings.ProposeConfig = map[[48]byte]*proposer.Option{pubkey: {GraffitiConfig: &proposer.GraffitiConfig{Graffiti: string(graffiti)}}}
		return v.SetProposerSettings(ctx, settings)
	}
	option, ok := settings.ProposeConfig[pubkey]
	if !ok || option == nil {
		settings.ProposeConfig[pubkey] = &proposer.Option{GraffitiConfig: &proposer.GraffitiConfig{
			Graffiti: string(graffiti),
		}}
	} else {
		option.GraffitiConfig = &proposer.GraffitiConfig{
			Graffiti: string(graffiti),
		}
	}
	return v.SetProposerSettings(ctx, settings) // save the proposer settings
}

func (v *validator) DeleteGraffiti(ctx context.Context, pubKey [fieldparams.BLSPubkeyLength]byte) error {
	ctx, span := trace.StartSpan(ctx, "validator.DeleteGraffiti")
	defer span.End()

	if v.proposerSettings == nil || v.proposerSettings.ProposeConfig == nil {
		return errors.New("attempted to delete graffiti without proposer settings, graffiti will default to flag options")
	}
	ps := v.proposerSettings.Clone()
	option, ok := ps.ProposeConfig[pubKey]
	if !ok || option == nil {
		return fmt.Errorf("graffiti not found in proposer settings for pubkey:%s", hexutil.Encode(pubKey[:]))
	}
	option.GraffitiConfig = nil
	return v.SetProposerSettings(ctx, ps) // save the proposer settings
}

func blockLogFields(pubKey [fieldparams.BLSPubkeyLength]byte, blk interfaces.ReadOnlyBeaconBlock, sig []byte) logrus.Fields {
	fields := logrus.Fields{
		"proposerPublicKey": fmt.Sprintf("%#x", pubKey),
		"proposerIndex":     blk.ProposerIndex(),
		"blockSlot":         blk.Slot(),
	}
	if sig != nil {
		fields["signature"] = fmt.Sprintf("%#x", sig)
	}
	return fields
}
