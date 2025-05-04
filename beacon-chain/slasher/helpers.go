package slasher

import (
	"bytes"
	"context"
	"fmt"
	"strconv"

	"github.com/OffchainLabs/prysm/v6/beacon-chain/db/slasherkv"
	slashertypes "github.com/OffchainLabs/prysm/v6/beacon-chain/slasher/types"
	fieldparams "github.com/OffchainLabs/prysm/v6/config/fieldparams"
	"github.com/OffchainLabs/prysm/v6/config/params"
	"github.com/OffchainLabs/prysm/v6/consensus-types/primitives"
	"github.com/OffchainLabs/prysm/v6/container/slice"
	ethpb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	"github.com/OffchainLabs/prysm/v6/runtime/version"
	"github.com/sirupsen/logrus"
)

// groupByValidatorChunkIndex organizes attestations into groups based on validator chunk indices.
// This grouping enables:
// 1. Concurrent processing of attestations for different validator chunks
// 2. Efficient use of 2D chunks for slashing detection
func (s *Service) groupByValidatorChunkIndex(
	attestations []*slashertypes.IndexedAttestationWrapper,
) map[uint64][]*slashertypes.IndexedAttestationWrapper {
	// Initialize map to store attestations grouped by validator chunk index
	groupedAttestations := make(map[uint64][]*slashertypes.IndexedAttestationWrapper)

	// The validatorChunkIndex groups validators into smaller sets for efficient block selection.
	// default params set for ValidatorChunkIndex is 256.
	// If there are 100,000 validators and they are split into 1,000 chunks, a validator with index
	// 25,678 might be in chunk 25. This helps Ethereum process validator roles faster in PBS and MEV-Boost.

	// Process each attestation
	for _, attestation := range attestations {
		// Track unique chunk indices for this attestation
		// We use a map to avoid duplicate chunk indices
		validatorChunkIndexes := make(map[uint64]bool)

		// For each validator that signed this attestation
		for _, validatorIndex := range attestation.IndexedAttestation.GetAttestingIndices() {
			// Calculate which chunk this validator belongs to
			validatorChunkIndex := s.params.validatorChunkIndex(primitives.ValidatorIndex(validatorIndex))
			// Record this chunk index (map ensures uniqueness)
			validatorChunkIndexes[validatorChunkIndex] = true
		}
		// Add this attestation to each relevant chunk group
		for validatorChunkIndex := range validatorChunkIndexes {
			// Append attestation to the list for this chunk index
			groupedAttestations[validatorChunkIndex] = append(
				groupedAttestations[validatorChunkIndex],
				attestation,
			)
		}
	}

	return groupedAttestations
}

// Group attestations by the chunk index their source epoch corresponds to.

func (s *Service) groupByChunkIndex(
	attestations []*slashertypes.IndexedAttestationWrapper,
) map[uint64][]*slashertypes.IndexedAttestationWrapper {
	attestationsByChunkIndex := make(map[uint64][]*slashertypes.IndexedAttestationWrapper)

	for _, attestation := range attestations {
		chunkIndex := s.params.chunkIndex(attestation.IndexedAttestation.GetData().Source.Epoch)
		attestationsByChunkIndex[chunkIndex] = append(attestationsByChunkIndex[chunkIndex], attestation)
	}

	return attestationsByChunkIndex
}

// This function returns a list of valid attestations, a list of attestations that are
// valid in the future, and the number of attestations dropped.
func (s *Service) filterAttestations(
	attWrappers []*slashertypes.IndexedAttestationWrapper, currentEpoch primitives.Epoch,
) (valid, validInFuture []*slashertypes.IndexedAttestationWrapper, numDropped int) {
	valid = make([]*slashertypes.IndexedAttestationWrapper, 0, len(attWrappers))
	validInFuture = make([]*slashertypes.IndexedAttestationWrapper, 0, len(attWrappers))

	for _, attWrapper := range attWrappers {
		if attWrapper == nil || !validateAttestationIntegrity(attWrapper.IndexedAttestation) {
			numDropped++
			continue
		}

		// If an attestation's source is epoch is older than the max history length
		// we keep track of for slashing detection, we drop it.
		if attWrapper.IndexedAttestation.GetData().Source.Epoch+s.params.historyLength <= currentEpoch {
			numDropped++
			continue
		}

		// If an attestation's target epoch is in the future, we defer processing for later.
		if attWrapper.IndexedAttestation.GetData().Target.Epoch > currentEpoch {
			validInFuture = append(validInFuture, attWrapper)
			continue
		}

		// The attestation is valid.
		valid = append(valid, attWrapper)
	}
	return
}

// Validates the attestation data integrity, ensuring we have no nil values for
// source and target epochs, and that the source epoch of the attestation must
// be less than the target epoch, which is a precondition for performing slashing
// detection (except for the genesis epoch).
func validateAttestationIntegrity(att ethpb.IndexedAtt) bool {
	// If an attestation is malformed, we drop it.
	if att == nil || att.IsNil() || att.GetData().Source == nil || att.GetData().Target == nil {
		return false
	}

	sourceEpoch := att.GetData().Source.Epoch
	targetEpoch := att.GetData().Target.Epoch

	// The genesis epoch is a special case, since all attestations formed in it
	// will have source and target 0, and they should be considered valid.
	if sourceEpoch == 0 && targetEpoch == 0 {
		return true
	}

	// All valid attestations must have source epoch < target epoch.
	return sourceEpoch < targetEpoch
}

// Validates the signed beacon block header integrity, ensuring we have no nil values.
func validateBlockHeaderIntegrity(header *ethpb.SignedBeaconBlockHeader) bool {
	// If a signed block header is malformed, we drop it.
	if header == nil ||
		header.Header == nil ||
		len(header.Signature) != fieldparams.BLSSignatureLength ||
		bytes.Equal(header.Signature, make([]byte, fieldparams.BLSSignatureLength)) {
		return false
	}
	return true
}

func logAttesterSlashing(slashing ethpb.AttSlashing) {
	indices := slice.IntersectionUint64(slashing.FirstAttestation().GetAttestingIndices(), slashing.SecondAttestation().GetAttestingIndices())
	log.WithFields(logrus.Fields{
		"validatorIndex":  indices,
		"prevSourceEpoch": slashing.FirstAttestation().GetData().Source.Epoch,
		"prevTargetEpoch": slashing.FirstAttestation().GetData().Target.Epoch,
		"sourceEpoch":     slashing.SecondAttestation().GetData().Source.Epoch,
		"targetEpoch":     slashing.SecondAttestation().GetData().Target.Epoch,
	}).Info("Attester slashing detected")
}

func logProposerSlashing(slashing *ethpb.ProposerSlashing) {
	log.WithFields(logrus.Fields{
		"validatorIndex": slashing.Header_1.Header.ProposerIndex,
		"slot":           slashing.Header_1.Header.Slot,
	}).Info("Proposer slashing detected")
}

// Turns a uint64 value to a string representation.
func uintToString(val uint64) string {
	return strconv.FormatUint(val, 10)
}

// If an existing signing root does not match an incoming proposal signing root,
// we then have a double block proposer slashing event.
func isDoubleProposal(incomingSigningRoot, existingSigningRoot [32]byte) bool {
	// If the existing signing root is the zero hash, we do not consider
	// this a double proposal.
	if existingSigningRoot == params.BeaconConfig().ZeroHash {
		return false
	}
	return incomingSigningRoot != existingSigningRoot
}

type GetChunkFromDatabaseFilters struct {
	ChunkKind                     slashertypes.ChunkKind
	ValidatorIndex                primitives.ValidatorIndex
	SourceEpoch                   primitives.Epoch
	IsDisplayAllValidatorsInChunk bool
	IsDisplayAllEpochsInChunk     bool
}

// GetChunkFromDatabase Utility function aiming at retrieving a chunk from the
// database.
func GetChunkFromDatabase(
	ctx context.Context,
	dbPath string,
	filters GetChunkFromDatabaseFilters,
	params *Parameters,
) (lastEpochForValidatorIndex primitives.Epoch, chunkIndex, validatorChunkIndex uint64, chunk Chunker, err error) {
	// init store
	d, err := slasherkv.NewKVStore(ctx, dbPath)
	if err != nil {
		return lastEpochForValidatorIndex, chunkIndex, validatorChunkIndex, chunk, fmt.Errorf("could not open database at path %s: %w", dbPath, err)
	}
	defer closeDB(d)

	// init service
	s := Service{
		params: params,
		serviceCfg: &ServiceConfig{
			Database: d,
		},
	}

	// variables
	validatorIndex := filters.ValidatorIndex
	sourceEpoch := filters.SourceEpoch
	chunkKind := filters.ChunkKind
	validatorChunkIndex = s.params.validatorChunkIndex(validatorIndex)
	chunkIndex = s.params.chunkIndex(sourceEpoch)

	// before getting the chunk, we need to verify if the requested epoch is in database
	lastEpochForValidator, err := s.serviceCfg.Database.LastEpochWrittenForValidators(ctx, []primitives.ValidatorIndex{validatorIndex})
	if err != nil {
		return lastEpochForValidatorIndex,
			chunkIndex,
			validatorChunkIndex,
			chunk,
			fmt.Errorf("could not get last epoch written for validator %d: %w", validatorIndex, err)
	}

	if len(lastEpochForValidator) == 0 {
		return lastEpochForValidatorIndex,
			chunkIndex,
			validatorChunkIndex,
			chunk,
			fmt.Errorf("could not get information at epoch %d for validator %d: there's no record found in slasher database",
				sourceEpoch, validatorIndex,
			)
	}
	lastEpochForValidatorIndex = lastEpochForValidator[0].Epoch

	// if the epoch requested is within the range, we can proceed to get the chunk, otherwise return error
	atBestSmallestEpoch := lastEpochForValidatorIndex.Sub(uint64(params.historyLength))
	if sourceEpoch < atBestSmallestEpoch || sourceEpoch > lastEpochForValidatorIndex {
		return lastEpochForValidatorIndex,
			chunkIndex,
			validatorChunkIndex,
			chunk,
			fmt.Errorf("requested epoch %d is outside the slasher history length %d, data can be provided within the epoch range [%d:%d] for validator %d",
				sourceEpoch, params.historyLength, atBestSmallestEpoch, lastEpochForValidatorIndex, validatorIndex,
			)
	}

	// fetch chunk from DB
	chunk, err = s.getChunkFromDatabase(ctx, chunkKind, validatorChunkIndex, chunkIndex)
	if err != nil {
		return lastEpochForValidatorIndex,
			chunkIndex,
			validatorChunkIndex,
			chunk,
			fmt.Errorf("could not get chunk at index %d: %w", chunkIndex, err)
	}

	return lastEpochForValidatorIndex, chunkIndex, validatorChunkIndex, chunk, nil
}

func closeDB(d *slasherkv.Store) {
	if err := d.Close(); err != nil {
		log.WithError(err).Error("could not close database")
	}
}

// unifyAttWrapperVersion ensures that the two wrappers wrap indexed attestations of the same version.
// If versions differ, the wrapped attestation with the lower version will be converted to the higher version.
func unifyAttWrapperVersion(w1 *slashertypes.IndexedAttestationWrapper, w2 *slashertypes.IndexedAttestationWrapper) {
	if w1.IndexedAttestation.Version() == w2.IndexedAttestation.Version() {
		return
	}
	if w1.IndexedAttestation.Version() != version.Electra {
		w1.IndexedAttestation = &ethpb.IndexedAttestationElectra{
			AttestingIndices: w1.IndexedAttestation.GetAttestingIndices(),
			Data:             w1.IndexedAttestation.GetData(),
			Signature:        w1.IndexedAttestation.GetSignature(),
		}
		return
	}
	w2.IndexedAttestation = &ethpb.IndexedAttestationElectra{
		AttestingIndices: w2.IndexedAttestation.GetAttestingIndices(),
		Data:             w2.IndexedAttestation.GetData(),
		Signature:        w2.IndexedAttestation.GetSignature(),
	}
}
