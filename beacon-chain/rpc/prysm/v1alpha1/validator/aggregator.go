package validator

import (
	"context"

	"github.com/OffchainLabs/prysm/v6/beacon-chain/cache"
	"github.com/OffchainLabs/prysm/v6/beacon-chain/core/helpers"
	"github.com/OffchainLabs/prysm/v6/beacon-chain/rpc/core"
	"github.com/OffchainLabs/prysm/v6/config/features"
	"github.com/OffchainLabs/prysm/v6/config/params"
	"github.com/OffchainLabs/prysm/v6/consensus-types/primitives"
	"github.com/OffchainLabs/prysm/v6/encoding/bytesutil"
	"github.com/OffchainLabs/prysm/v6/monitoring/tracing/trace"
	ethpb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	"github.com/OffchainLabs/prysm/v6/time/slots"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Deprecated: The gRPC API will remain the default and fully supported through v8 (expected in 2026) but will be eventually removed in favor of REST API.
//
// SubmitAggregateSelectionProof is called by a validator when its assigned to be an aggregator.
// The aggregator submits the selection proof to obtain the aggregated attestation
// object to sign over.
func (vs *Server) SubmitAggregateSelectionProof(ctx context.Context, req *ethpb.AggregateSelectionRequest) (*ethpb.AggregateSelectionResponse, error) {
	ctx, span := trace.StartSpan(ctx, "AggregatorServer.SubmitAggregateSelectionProof")
	defer span.End()
	span.SetAttributes(trace.Int64Attribute("slot", int64(req.Slot)))

	// The function checks several conditions: the node must be synced, the validator must exist
	// and be active, and most importantly, the validator must be randomly selected as an aggregator their signature.
	// If all checks pass, the function returns the validator's index and validator's index in committee.
	indexInCommittee, validatorIndex, err := vs.processAggregateSelection(ctx, req)
	if err != nil {
		return nil, err
	}

	var atts []*ethpb.Attestation

	if features.Get().EnableExperimentalAttestationPool {
		// GetBySlotAndCommitteeIndex returns all attestations in the cache that match the provided slot
		// and committee index. Forkchoice attestations are not returned.
		atts = cache.GetBySlotAndCommitteeIndex[*ethpb.Attestation](vs.AttestationCache, req.Slot, req.CommitteeIndex)
	} else {
		// AggregatedAttestationsBySlotIndex returns the aggregated attestations in cache,
		// filtered by committee index and slot.
		atts = vs.AttPool.AggregatedAttestationsBySlotIndex(ctx, req.Slot, req.CommitteeIndex)
		if len(atts) == 0 {
			// UnaggregatedAttestationsBySlotIndex returns the unaggregated attestations in cache,
			// filtered by committee index and slot.
			atts = vs.AttPool.UnaggregatedAttestationsBySlotIndex(ctx, req.Slot, req.CommitteeIndex)
		}
	}
	if len(atts) == 0 {
		return nil, status.Errorf(codes.NotFound, "Could not find attestation for slot and committee in pool")
	}
	// bestAggregate function finds the best attestation from a list of attestations. It has two main priorities:
	// - First Priority: It looks for attestations that contain the validator's own signature (using BitAt)
	// and has the most votes (using Count)
	// - Second Priority: If it can't find an attestation with the validator's signature, it simply picks
	// the one with the most votes
	// - Think of it like picking the best group attendance sheet: first try to find a sheet that has your own
	// signature and the most people signed in, but if you can't find one with your signature, just take the
	// sheet with the most signatures overall.
	best := bestAggregate(atts, req.CommitteeIndex, indexInCommittee)
	attAndProof := &ethpb.AggregateAttestationAndProof{
		Aggregate:       best,
		SelectionProof:  req.SlotSignature,
		AggregatorIndex: validatorIndex,
	}
	return &ethpb.AggregateSelectionResponse{AggregateAndProof: attAndProof}, nil
}

// Deprecated: The gRPC API will remain the default and fully supported through v8 (expected in 2026) but will be eventually removed in favor of REST API.
//
// SubmitAggregateSelectionProofElectra is called by a validator when its assigned to be an aggregator.
// The aggregator submits the selection proof to obtain the aggregated attestation
// object to sign over.
func (vs *Server) SubmitAggregateSelectionProofElectra(
	ctx context.Context,
	req *ethpb.AggregateSelectionRequest,
) (*ethpb.AggregateSelectionElectraResponse, error) {
	ctx, span := trace.StartSpan(ctx, "AggregatorServer.SubmitAggregateSelectionProofElectra")
	defer span.End()
	span.SetAttributes(trace.Int64Attribute("slot", int64(req.Slot)))

	// The function checks several conditions: the node must be synced, the validator must exist
	// and be active, and most importantly, the validator must be randomly selected as an aggregator their signature.
	// If all checks pass, the function returns the validator's index and validator's index in committee.
	indexInCommittee, validatorIndex, err := vs.processAggregateSelection(ctx, req)
	if err != nil {
		return nil, err
	}

	var atts []*ethpb.AttestationElectra

	if features.Get().EnableExperimentalAttestationPool {
		// GetBySlotAndCommitteeIndex returns all attestations in the cache that match the provided slot
		// and committee index. Forkchoice attestations are not returned.
		atts = cache.GetBySlotAndCommitteeIndex[*ethpb.AttestationElectra](vs.AttestationCache, req.Slot, req.CommitteeIndex)
	} else {
		// AggregatedAttestationsBySlotIndexElectra returns the aggregated attestations in cache,
		// filtered by committee index and slot.
		atts = vs.AttPool.AggregatedAttestationsBySlotIndexElectra(ctx, req.Slot, req.CommitteeIndex)
		if len(atts) == 0 {
			// UnaggregatedAttestationsBySlotIndexElectra returns the unaggregated attestations in cache,
			// filtered by committee index and slot.
			atts = vs.AttPool.UnaggregatedAttestationsBySlotIndexElectra(ctx, req.Slot, req.CommitteeIndex)
		}
	}
	if len(atts) == 0 {
		return nil, status.Errorf(codes.NotFound, "Could not find attestation for slot and committee in pool")
	}
	// bestAggregate function finds the best attestation from a list of attestations. It has two main priorities:
	// - First Priority: It looks for attestations that contain the validator's own signature (using BitAt)
	// and has the most votes (using Count)
	// - Second Priority: If it can't find an attestation with the validator's signature, it simply picks
	// the one with the most votes
	// - Think of it like picking the best group attendance sheet: first try to find a sheet that has your own
	//  signature and the most people signed in, but if you can't find one with your signature, just take the
	// sheet with the most signatures overall.
	best := bestAggregate(atts, req.CommitteeIndex, indexInCommittee)
	attAndProof := &ethpb.AggregateAttestationAndProofElectra{
		Aggregate:       best,
		SelectionProof:  req.SlotSignature,
		AggregatorIndex: validatorIndex,
	}
	return &ethpb.AggregateSelectionElectraResponse{AggregateAndProof: attAndProof}, nil
}

func (vs *Server) processAggregateSelection(ctx context.Context, req *ethpb.AggregateSelectionRequest) (uint64, primitives.ValidatorIndex, error) {
	if vs.SyncChecker.Syncing() {
		return 0, 0, status.Errorf(codes.Unavailable, "Syncing to latest head, not ready to respond")
	}

	// An optimistic validator MUST NOT participate in attestation
	// (i.e., sign across the DOMAIN_BEACON_ATTESTER, DOMAIN_SELECTION_PROOF or DOMAIN_AGGREGATE_AND_PROOF domains).
	if err := vs.optimisticStatus(ctx); err != nil {
		return 0, 0, err
	}
	// HeadStateReadOnly returns the read only head state of the chain.
	// If the head is nil from service struct, it will attempt to get the
	// head state from DB. Any callers of this method MUST only use the
	// state instance to read fields from the state. Any type assertions back
	// to the concrete type and subsequent use of it could lead to corruption
	// of the state.
	st, err := vs.HeadFetcher.HeadStateReadOnly(ctx)
	if err != nil {
		return 0, 0, status.Errorf(codes.Internal, "Could not determine head state: %v", err)
	}

	// ValidatorIndexByPubkey returns a given validator by its 48-byte public key.
	validatorIndex, exists := st.ValidatorIndexByPubkey(bytesutil.ToBytes48(req.PublicKey))
	if !exists {
		return 0, 0, status.Error(codes.Internal, "Could not locate validator index in DB")
	}

	//
	epoch := slots.ToEpoch(req.Slot)
	activeValidatorIndices, err := helpers.ActiveValidatorIndices(ctx, st, epoch)
	if err != nil {
		return 0, 0, status.Errorf(codes.Internal, "Could not get validators: %v", err)
	}
	seed, err := helpers.Seed(st, epoch, params.BeaconConfig().DomainBeaconAttester)
	if err != nil {
		return 0, 0, status.Errorf(codes.Internal, "Could not get seed: %v", err)
	}
	committee, err := helpers.BeaconCommittee(ctx, activeValidatorIndices, seed, req.Slot, req.CommitteeIndex)
	if err != nil {
		return 0, 0, err
	}

	// IsAggregator returns true if the signature is from the input validator. The committee
	// count is provided as an argument rather than imported implementation from spec. Having
	// committee count as an argument allows cheaper computation at run time.
	isAggregator, err := helpers.IsAggregator(uint64(len(committee)), req.SlotSignature)
	if err != nil {
		return 0, 0, status.Errorf(codes.Internal, "Could not get aggregator status: %v", err)
	}
	if !isAggregator {
		return 0, 0, status.Errorf(codes.InvalidArgument, "Validator is not an aggregator")
	}

	var indexInCommittee uint64
	for i, idx := range committee {
		if idx == validatorIndex {
			indexInCommittee = uint64(i)
		}
	}
	return indexInCommittee, validatorIndex, nil
}

// Deprecated: The gRPC API will remain the default and fully supported through v8 (expected in 2026) but will be eventually removed in favor of REST API.
//
// SubmitSignedAggregateSelectionProof is called by a validator to broadcast a signed
// aggregated and proof object.
func (vs *Server) SubmitSignedAggregateSelectionProof(
	ctx context.Context,
	req *ethpb.SignedAggregateSubmitRequest,
) (*ethpb.SignedAggregateSubmitResponse, error) {
	if err := vs.CoreService.SubmitSignedAggregateSelectionProof(ctx, req.SignedAggregateAndProof); err != nil {
		return nil, status.Errorf(core.ErrorReasonToGRPC(err.Reason), "Could not submit aggregate: %v", err.Err)
	}
	return &ethpb.SignedAggregateSubmitResponse{}, nil
}

// Deprecated: The gRPC API will remain the default and fully supported through v8 (expected in 2026) but will be eventually removed in favor of REST API.
//
// SubmitSignedAggregateSelectionProofElectra is called by a validator to broadcast a signed
// aggregated and proof object.
func (vs *Server) SubmitSignedAggregateSelectionProofElectra(
	ctx context.Context,
	req *ethpb.SignedAggregateSubmitElectraRequest,
) (*ethpb.SignedAggregateSubmitResponse, error) {
	if err := vs.CoreService.SubmitSignedAggregateSelectionProof(ctx, req.SignedAggregateAndProof); err != nil {
		return nil, status.Errorf(core.ErrorReasonToGRPC(err.Reason), "Could not submit aggregate: %v", err.Err)
	}
	return &ethpb.SignedAggregateSubmitResponse{}, nil
}

// bestAggregate function finds the best attestation from a list of attestations. It has two main priorities:
// - First Priority: It looks for attestations that contain the validator's own signature (using BitAt)
// and has the most votes (using Count)
// - Second Priority: If it can't find an attestation with the validator's signature, it simply picks
// the one with the most votes
//   - Think of it like picking the best group attendance sheet: first try to find a sheet that has your own
//     signature and the most people signed in, but if you can't find one with your signature, just take the
//
// sheet with the most signatures overall.
func bestAggregate[T ethpb.Att](atts []T, committeeIndex primitives.CommitteeIndex, indexInCommittee uint64) T {
	best := atts[0]
	for _, a := range atts[1:] {
		// The aggregator should prefer an attestation that they have signed. We check this by
		// looking at the attestation's committee index against the validator's committee index
		// and check the aggregate bits to ensure the validator's index is set.

		// - BitAt returns true if the bit at the given index is 1.
		// - Count returns the number of 1s in the bitfield.
		if a.CommitteeBitsVal().BitAt(uint64(committeeIndex)) &&
			a.GetAggregationBits().BitAt(indexInCommittee) &&
			(!best.GetAggregationBits().BitAt(indexInCommittee) ||
				a.GetAggregationBits().Count() > best.GetAggregationBits().Count()) {
			best = a
		}

		// If the "best" still doesn't contain the validator's index, check the aggregation bits to
		// choose the attestation with the most bits set.
		if !best.GetAggregationBits().BitAt(indexInCommittee) &&
			a.GetAggregationBits().Count() > best.GetAggregationBits().Count() {
			best = a
		}
	}
	return best
}
