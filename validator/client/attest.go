package client

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/OffchainLabs/prysm/v6/async"
	"github.com/OffchainLabs/prysm/v6/beacon-chain/core/signing"
	"github.com/OffchainLabs/prysm/v6/config/features"
	fieldparams "github.com/OffchainLabs/prysm/v6/config/fieldparams"
	"github.com/OffchainLabs/prysm/v6/config/params"
	"github.com/OffchainLabs/prysm/v6/consensus-types/primitives"
	"github.com/OffchainLabs/prysm/v6/encoding/bytesutil"
	"github.com/OffchainLabs/prysm/v6/monitoring/tracing"
	"github.com/OffchainLabs/prysm/v6/monitoring/tracing/trace"
	ethpb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	validatorpb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1/validator-client"
	prysmTime "github.com/OffchainLabs/prysm/v6/time"
	"github.com/OffchainLabs/prysm/v6/time/slots"
	"github.com/OffchainLabs/prysm/v6/validator/client/iface"
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/sirupsen/logrus"
)

var failedAttLocalProtectionErr = "attempted to make slashable attestation, rejected by local slashing protection"

// SubmitAttestation completes the validator client's attester responsibility at a given slot.
// It fetches the latest beacon block head along with the latest canonical beacon state
// information in order to sign the block and include information about the validator's
// participation in voting on the block.
func (v *validator) SubmitAttestation(ctx context.Context, slot primitives.Slot, pubKey [fieldparams.BLSPubkeyLength]byte) {
	ctx, span := trace.StartSpan(ctx, "validator.SubmitAttestation")
	defer span.End()
	span.SetAttributes(trace.StringAttribute("validator", fmt.Sprintf("%#x", pubKey)))

	// The validator waits until one of two conditions is met:
	// - One-third of the slot time has passed.
	// - A valid block for the slot has been received.
	v.waitOneThirdOrValidBlock(ctx, slot)

	// appends a byte to the strings.Builder to create a lock key. 
	// This byte represents the validator's role.
	var b strings.Builder
	if err := b.WriteByte(byte(iface.RoleAttester)); err != nil {
		log.WithError(err).Error("Could not write role byte for lock key")
		tracing.AnnotateError(span, err)
		return
	}

	// It appends the validator's public key (a byte array) to the strings.Builder
	_, err := b.Write(pubKey[:])
	if err != nil {
		log.WithError(err).Error("Could not write pubkey bytes for lock key")
		tracing.AnnotateError(span, err)
		return
	}

	// It creates a lock using the string built by strings.Builder (which contains the validator's role and public key).
	// The lock ensures that only one instance of the validator can perform a specific task (e.g., attesting) at a time.
	lock := async.NewMultilock(b.String())
	lock.Lock()
	defer lock.Unlock()

	// It converts the public key (a byte array) into a hexadecimal string for easier readability.
	fmtKey := fmt.Sprintf("%#x", pubKey[:])
	log := log.WithField("pubkey", fmt.Sprintf("%#x", bytesutil.Trunc(pubKey[:]))).WithField("slot", slot)
	// Given the validator public key, this gets the validator assignment.
	// - It fetches the validator's role and committee for the slot.
	// - If the validator isn’t part of any committee, it skips attesting.
	duty, err := v.duty(pubKey)
	if err != nil {
		log.WithError(err).Error("Could not fetch validator assignment")
		if v.emitAccountMetrics {
			ValidatorAttestFailVec.WithLabelValues(fmtKey).Inc()
		}
		tracing.AnnotateError(span, err)
		return
	}
	if duty.CommitteeLength == 0 {
		log.Debug("Empty committee for validator duty, not attesting")
		return
	}


	
	req := &ethpb.AttestationDataRequest{
		Slot:           slot,
		CommitteeIndex: duty.CommitteeIndex,
	}
	// This function is used by a validator to request attestation data from the beacon node. 
	// Attestation data is the information a validator needs to create a signed attestation
	// (a vote on a block).
	// beacon-chain/rpc/prysm/v1alpha1/validator/attester.go
	data, err := v.validatorClient.AttestationData(ctx, req)
	if err != nil {
		log.WithError(err).Error("Could not request attestation to sign at slot")
		if v.emitAccountMetrics {
			ValidatorAttestFailVec.WithLabelValues(fmtKey).Inc()
		}
		tracing.AnnotateError(span, err)
		return
	}

	// Given validator's public key, this function returns the signature of an attestation data and its signing root.
	// - The validator signs the attestation data to prove its participation.
	sig, _, err := v.signAtt(ctx, pubKey, data, slot)
	if err != nil {
		log.WithError(err).Error("Could not sign attestation")
		if v.emitAccountMetrics {
			ValidatorAttestFailVec.WithLabelValues(fmtKey).Inc()
		}
		tracing.AnnotateError(span, err)
		return
	}

	postElectra := slots.ToEpoch(slot) >= params.BeaconConfig().ElectraForkEpoch
	// The validator creates the attestation object  in the correct format 
	// (depending on the blockchain fork, e.g., Electra or earlier)., which includes:
	// - The attestation data.
	// - The validator’s signature.
	// - The validator’s index in the committee.
	var indexedAtt ethpb.IndexedAtt
	if postElectra {
		indexedAtt = &ethpb.IndexedAttestationElectra{
			AttestingIndices: []uint64{uint64(duty.ValidatorIndex)},
			Data:             data,
			Signature:        sig,
		}
	} else {
		indexedAtt = &ethpb.IndexedAttestation{
			AttestingIndices: []uint64{uint64(duty.ValidatorIndex)},
			Data:             data,
			Signature:        sig,
		}
	}
	
	// domainAndSigningRoot returns the domain and signing root for an attestation.
	// A domain is a unique identifier that ensures data (like attestations or blocks) is 
	// only valid for a specific purpose, fork, or epoch. It prevents data from being misused 
	// or replayed in the wrong context.
	_, signingRoot, err := v.domainAndSigningRoot(ctx, indexedAtt.GetData())
	if err != nil {
		log.WithError(err).Error("Could not get domain and signing root from attestation")
		if v.emitAccountMetrics {
			ValidatorAttestFailVec.WithLabelValues(fmtKey).Inc()
		}
		tracing.AnnotateError(span, err)
		return
	}

	// Send the attestation to the beacon node.
	// SlashableAttestationCheck checks if an attestation is slashable by comparing it with the attesting
	// history for the given public key in our complete slashing protection database defined by EIP-3076.
	// If it is not, it updates the database.
	if err := v.db.SlashableAttestationCheck(ctx, indexedAtt, pubKey, signingRoot, v.emitAccountMetrics, ValidatorAttestFailVec); err != nil {
		log.WithError(err).Error("Failed attestation slashing protection check")
		log.WithFields(
			attestationLogFields(pubKey, indexedAtt),
		).Debug("Attempted slashable attestation details")
		tracing.AnnotateError(span, err)
		return
	}

	var aggregationBitfield bitfield.Bitlist
	var attestation ethpb.Att
	var attResp *ethpb.AttestResponse
	if postElectra {
		sa := &ethpb.SingleAttestation{
			Data:          data,
			AttesterIndex: duty.ValidatorIndex,
			CommitteeId:   duty.CommitteeIndex,
			Signature:     sig,
		}
<<<<<<< HEAD
		// ProposeAttestationElectra is a function called by an attester to vote
		// on a block via an attestation object as defined in the Ethereum specification.
		// - It allows a validator to vote on a block by submitting an attestation
		// beacon-chain/rpc/prysm/v1alpha1/validator/attester.go
		attResp, err = v.validatorClient.ProposeAttestationElectra(ctx, attestation)
	} else {
		var indexInCommittee uint64
		var found bool
		// Find the Validator’s Index in the Committee
		for i, vID := range duty.Committee {
			if vID == duty.ValidatorIndex {
				indexInCommittee = uint64(i)
				found = true
				break
			}
		}
		// If the validator is not found in the committee, it logs an error, increments 
		// a failure metric (if enabled), and stops.
		if !found {
			log.Errorf("Validator ID %d not found in committee of %v", duty.ValidatorIndex, duty.Committee)
			if v.emitAccountMetrics {
				ValidatorAttestFailVec.WithLabelValues(fmtKey).Inc()
			}
			return
		}
		// A bitfield (a list of bits) is created to represent which validators in the committee have signed the attestation.
		aggregationBitfield = bitfield.NewBitlist(uint64(len(duty.Committee)))
		// The bit corresponding to the validator’s index is set to true
		aggregationBitfield.SetBitAt(indexInCommittee, true)
		attestation := &ethpb.Attestation{
=======
		attestation = sa
		attResp, err = v.validatorClient.ProposeAttestationElectra(ctx, sa)
	} else {
		aggregationBitfield = bitfield.NewBitlist(duty.CommitteeLength)
		aggregationBitfield.SetBitAt(duty.ValidatorCommitteeIndex, true)
		a := &ethpb.Attestation{
>>>>>>> 204302a821da57632ec4e2d89126a21f00bd2817
			Data:            data,
			AggregationBits: aggregationBitfield,
			Signature:       sig,
		}
<<<<<<< HEAD
		// Finally, you submit your attestation to the beacon node. The beacon node broadcasts
		// it to the network, and other validators include it in the blockchain.
		attResp, err = v.validatorClient.ProposeAttestation(ctx, attestation)
=======
		attestation = a
		attResp, err = v.validatorClient.ProposeAttestation(ctx, a)
>>>>>>> 204302a821da57632ec4e2d89126a21f00bd2817
	}
	if err != nil {
		log.WithError(err).Error("Could not submit attestation to beacon node")
		if v.emitAccountMetrics {
			ValidatorAttestFailVec.WithLabelValues(fmtKey).Inc()
		}
		tracing.AnnotateError(span, err)
		return
	}
<<<<<<< HEAD
	// saveSubmittedAtt saves the submitted attestation data along with the attester's pubkey.
	// The purpose of this is to display combined attesting logs for all keys managed by the validator client.
	if err := v.saveSubmittedAtt(data, pubKey[:], false); err != nil {
=======

	if err := v.saveSubmittedAtt(attestation, pubKey[:], false); err != nil {
>>>>>>> 204302a821da57632ec4e2d89126a21f00bd2817
		log.WithError(err).Error("Could not save validator index for logging")
		if v.emitAccountMetrics {
			ValidatorAttestFailVec.WithLabelValues(fmtKey).Inc()
		}
		tracing.AnnotateError(span, err)
		return
	}

	span.SetAttributes(
		trace.Int64Attribute("slot", int64(slot)), // lint:ignore uintcast -- This conversion is OK for tracing.
		trace.StringAttribute("attestationHash", fmt.Sprintf("%#x", attResp.AttestationDataRoot)),
		trace.StringAttribute("blockRoot", fmt.Sprintf("%#x", data.BeaconBlockRoot)),
		trace.Int64Attribute("justifiedEpoch", int64(data.Source.Epoch)),
		trace.Int64Attribute("targetEpoch", int64(data.Target.Epoch)),
	)
	if postElectra {
		span.SetAttributes(trace.Int64Attribute("attesterIndex", int64(duty.ValidatorIndex)))
		span.SetAttributes(trace.Int64Attribute("committeeIndex", int64(duty.CommitteeIndex)))
	} else {
		span.SetAttributes(trace.StringAttribute("aggregationBitfield", fmt.Sprintf("%#x", aggregationBitfield)))
		span.SetAttributes(trace.Int64Attribute("committeeIndex", int64(data.CommitteeIndex)))
	}

	// The function updates metrics and tracing information to track the validator’s performance.
	if v.emitAccountMetrics {
		ValidatorAttestSuccessVec.WithLabelValues(fmtKey).Inc()
		ValidatorAttestedSlotsGaugeVec.WithLabelValues(fmtKey).Set(float64(slot))
	}
}

// Given the validator public key, this gets the validator assignment.
func (v *validator) duty(pubKey [fieldparams.BLSPubkeyLength]byte) (*ethpb.ValidatorDuty, error) {
	v.dutiesLock.RLock()
	defer v.dutiesLock.RUnlock()
	if v.duties == nil {
		return nil, errors.New("no duties for validators")
	}

	for _, duty := range v.duties.CurrentEpochDuties {
		if bytes.Equal(pubKey[:], duty.PublicKey) {
			return duty, nil
		}
	}

	return nil, fmt.Errorf("pubkey %#x not in duties", bytesutil.Trunc(pubKey[:]))
}

// Given validator's public key, this function returns the signature of an attestation data and its signing root.
func (v *validator) signAtt(ctx context.Context, pubKey [fieldparams.BLSPubkeyLength]byte, data *ethpb.AttestationData, slot primitives.Slot) ([]byte, [32]byte, error) {
	ctx, span := trace.StartSpan(ctx, "validator.signAtt")
	defer span.End()

	domain, root, err := v.domainAndSigningRoot(ctx, data)
	if err != nil {
		return nil, [32]byte{}, err
	}
	sig, err := v.km.Sign(ctx, &validatorpb.SignRequest{
		PublicKey:       pubKey[:],
		SigningRoot:     root[:],
		SignatureDomain: domain.SignatureDomain,
		Object:          &validatorpb.SignRequest_AttestationData{AttestationData: data},
		SigningSlot:     slot,
	})
	if err != nil {
		return nil, [32]byte{}, err
	}

	return sig.Marshal(), root, nil
}

func (v *validator) domainAndSigningRoot(ctx context.Context, data *ethpb.AttestationData) (*ethpb.DomainResponse, [32]byte, error) {
	// to get the domain for the attestation. The domain is a unique identifier for the attestation
	// A domain is a unique identifier that ensures data (like attestations or blocks) is only valid 
	// for a specific purpose, fork, or epoch. It prevents data from being misused or replayed in the wrong context.
	domain, err := v.domainData(ctx, data.Target.Epoch, params.BeaconConfig().DomainBeaconAttester[:])
	if err != nil {
		return nil, [32]byte{}, err
	}
	// ComputeSigningRoot computes the root of the object by calculating the hash tree root of the signing data with the given domain.
	root, err := signing.ComputeSigningRoot(data, domain.SignatureDomain)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return domain, root, nil
}

// highestSlot returns the highest slot with a valid block seen by the validator
func (v *validator) highestSlot() primitives.Slot {
	v.highestValidSlotLock.Lock()
	defer v.highestValidSlotLock.Unlock()
	return v.highestValidSlot
}

// setHighestSlot sets the highest slot with a valid block seen by the validator
func (v *validator) setHighestSlot(slot primitives.Slot) {
	v.highestValidSlotLock.Lock()
	defer v.highestValidSlotLock.Unlock()
	if slot > v.highestValidSlot {
		v.highestValidSlot = slot
		v.slotFeed.Send(slot)
	}
}

// waitOneThirdOrValidBlock waits until (a) or (b) whichever comes first:
//
//	(a) the validator has received a valid block that is the same slot as input slot
//	(b) one-third of the slot has transpired (SECONDS_PER_SLOT / 3 seconds after the start of slot)
func (v *validator) waitOneThirdOrValidBlock(ctx context.Context, slot primitives.Slot) {
	ctx, span := trace.StartSpan(ctx, "validator.waitOneThirdOrValidBlock")
	defer span.End()

	// Don't need to wait if requested slot is the same as highest valid slot.
	if slot <= v.highestSlot() {
		return
	}

	delay := slots.DivideSlotBy(3 /* a third of the slot duration */)
	startTime := slots.StartTime(v.genesisTime, slot)
	finalTime := startTime.Add(delay)
	wait := prysmTime.Until(finalTime)
	if wait <= 0 {
		return
	}
	t := time.NewTimer(wait)
	defer t.Stop()

	ch := make(chan primitives.Slot, 1)
	sub := v.slotFeed.Subscribe(ch)
	defer sub.Unsubscribe()

	for {
		select {
		case s := <-ch:
			if features.Get().AttestTimely {
				if slot <= s {
					return
				}
			}
		case <-ctx.Done():
			tracing.AnnotateError(span, ctx.Err())
			return
		case <-sub.Err():
			log.Error("Subscriber closed, exiting goroutine")
			return
		case <-t.C:
			return
		}
	}
}

func attestationLogFields(pubKey [fieldparams.BLSPubkeyLength]byte, indexedAtt ethpb.IndexedAtt) logrus.Fields {
	return logrus.Fields{
		"pubkey":         fmt.Sprintf("%#x", pubKey),
		"slot":           indexedAtt.GetData().Slot,
		"committeeIndex": indexedAtt.GetData().CommitteeIndex,
		"blockRoot":      fmt.Sprintf("%#x", indexedAtt.GetData().BeaconBlockRoot),
		"sourceEpoch":    indexedAtt.GetData().Source.Epoch,
		"sourceRoot":     fmt.Sprintf("%#x", indexedAtt.GetData().Source.Root),
		"targetEpoch":    indexedAtt.GetData().Target.Epoch,
		"targetRoot":     fmt.Sprintf("%#x", indexedAtt.GetData().Target.Root),
		"signature":      fmt.Sprintf("%#x", indexedAtt.GetSignature()),
	}
}
