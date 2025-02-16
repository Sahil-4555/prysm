package validator

import (
	"context"

	"github.com/prysmaticlabs/prysm/v5/beacon-chain/core/helpers"
	coreTime "github.com/prysmaticlabs/prysm/v5/beacon-chain/core/time"
	"github.com/prysmaticlabs/prysm/v5/beacon-chain/core/transition"
	"github.com/prysmaticlabs/prysm/v5/beacon-chain/rpc/core"
	"github.com/prysmaticlabs/prysm/v5/consensus-types/primitives"
	"github.com/prysmaticlabs/prysm/v5/encoding/bytesutil"
	ethpb "github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1"
	"github.com/prysmaticlabs/prysm/v5/time/slots"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// GetDuties returns the duties assigned to a list of validators specified
// in the request object.
func (vs *Server) GetDuties(ctx context.Context, req *ethpb.DutiesRequest) (*ethpb.DutiesResponse, error) {
	// Syncing returns true if initial sync is still running.
	if vs.SyncChecker.Syncing() {
		return nil, status.Error(codes.Unavailable, "Syncing to latest head, not ready to respond")
	}
	return vs.duties(ctx, req)
}

// Compute the validator duties from the head state's corresponding epoch
// for validators public key / indices requested.
func (vs *Server) duties(ctx context.Context, req *ethpb.DutiesRequest) (*ethpb.DutiesResponse, error) {
	// ToEpoch returns the epoch number of the input slot.
	currentEpoch := slots.ToEpoch(vs.TimeFetcher.CurrentSlot())
	if req.Epoch > currentEpoch+1 {
		return nil, status.Errorf(codes.Unavailable, "Request epoch %d can not be greater than next epoch %d", req.Epoch, currentEpoch+1)
	}

	// HeadState returns the head state of the chain (beaconState).
	// If the head is nil from service struct,
	// it will attempt to get the head state from DB.
	s, err := vs.HeadFetcher.HeadState(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Could not get head state: %v", err)
	}

	// Advance state with empty transitions up to the requested epoch start slot.
	// EpochStart returns the first slot number of the current epoch.
	epochStartSlot, err := slots.EpochStart(req.Epoch)
	if err != nil {
		return nil, err
	}
	if s.Slot() < epochStartSlot {
		headRoot, err := vs.HeadFetcher.HeadRoot(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "Could not retrieve head root: %v", err)
		}
		// ProcessSlotsUsingNextSlotCache processes slots by using next slot cache for higher efficiency.
		// return the beaconState
		s, err = transition.ProcessSlotsUsingNextSlotCache(ctx, s, headRoot, epochStartSlot)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "Could not process slots up to %d: %v", epochStartSlot, err)
		}
	}

	requestIndices := make([]primitives.ValidatorIndex, 0, len(req.PublicKeys))
	for _, pubKey := range req.PublicKeys {
		//  ValidatorIndexByPubkey returns a given validator by its 48-byte public key.
		idx, ok := s.ValidatorIndexByPubkey(bytesutil.ToBytes48(pubKey))
		if !ok {
			continue
		}
		requestIndices = append(requestIndices, idx)
	}

	// CommitteeAssignments calculates committee assignments for each validator during the specified epoch.
	// It retrieves active validator indices, determines the number of committees per slot, and computes
	// assignments for each validator based on their presence in the provided validators slice.
	assignments, err := helpers.CommitteeAssignments(ctx, s, req.Epoch, requestIndices)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Could not compute committee assignments: %v", err)
	}
	// Query the next epoch assignments for committee subnet subscriptions.
	nextEpochAssignments, err := helpers.CommitteeAssignments(ctx, s, req.Epoch+1, requestIndices)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Could not compute next committee assignments: %v", err)
	}

	// ProposerAssignments calculates proposer assignments for each validator 
	// during the specified epoch. It verifies the validity of the epoch, then 
	// iterates through each slot in the epoch to determine the proposer for that slot 
	// and assigns them accordingly.
	proposalSlots, err := helpers.ProposerAssignments(ctx, s, req.Epoch)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Could not compute proposer slots: %v", err)
	}

	validatorAssignments := make([]*ethpb.DutiesResponse_Duty, 0, len(req.PublicKeys))
	nextValidatorAssignments := make([]*ethpb.DutiesResponse_Duty, 0, len(req.PublicKeys))

	for _, pubKey := range req.PublicKeys {
		if ctx.Err() != nil {
			return nil, status.Errorf(codes.Aborted, "Could not continue fetching assignments: %v", ctx.Err())
		}
		assignment := &ethpb.DutiesResponse_Duty{
			PublicKey: pubKey,
		}
		nextAssignment := &ethpb.DutiesResponse_Duty{
			PublicKey: pubKey,
		}

		// ValidatorIndexByPubkey returns a given validator by its 48-byte public key
		idx, ok := s.ValidatorIndexByPubkey(bytesutil.ToBytes48(pubKey))
		if ok {
			// assignmentStatus determines the current status of a validator based on 
			// its activation and exit epochs, slashing status, and the current epoch. 
			// It returns the appropriate validator status such as ACTIVE, PENDING,
			// EXITING, SLASHING, or EXITED.
			s := assignmentStatus(s, idx)

			assignment.ValidatorIndex = idx
			assignment.Status = s
			assignment.ProposerSlots = proposalSlots[idx]

			// The next epoch has no lookup for proposer indexes.
			nextAssignment.ValidatorIndex = idx
			nextAssignment.Status = s

			ca, ok := assignments[idx]
			if ok {
				assignment.Committee = ca.Committee
				assignment.AttesterSlot = ca.AttesterSlot
				assignment.CommitteeIndex = ca.CommitteeIndex
			}
			// Save the next epoch assignments.
			ca, ok = nextEpochAssignments[idx]
			if ok {
				nextAssignment.Committee = ca.Committee
				nextAssignment.AttesterSlot = ca.AttesterSlot
				nextAssignment.CommitteeIndex = ca.CommitteeIndex
			}
		} else {
			// If the validator isn't in the beacon state, try finding their deposit to determine their status.
			// We don't need the lastActiveValidatorFn because we don't use the response in this.
			// validatorStatus searches for the requested validator's state and deposit to 
			// retrieve its inclusion estimate. Also returns the validators index.
			vStatus, _ := vs.validatorStatus(ctx, s, pubKey, nil)
			assignment.Status = vStatus.Status
		}

		// Are the validators in current or next epoch sync committee.
		// HigherEqualThanAltairVersionAndEpoch returns if the input state `s` has a higher version number 
		// than Altair state and input epoch `e` is higher equal than fork epoch.
		if ok && coreTime.HigherEqualThanAltairVersionAndEpoch(s, req.Epoch) {
			// IsCurrentPeriodSyncCommittee returns true if the input validator index belongs in 
			// the current period sync committee along with the sync committee root.
			// 1. Checks if the public key exists in the sync committee cache
			// 2. If 1 fails, checks if the public key exists in the input current sync committee object
			assignment.IsSyncCommittee, err = helpers.IsCurrentPeriodSyncCommittee(s, idx)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "Could not determine current epoch sync committee: %v", err)
			}
			if assignment.IsSyncCommittee {
			// RegisterSyncSubnetCurrentPeriodProto is registering this validator to a subnet (a network partition) 
			// for the current sync committee period.
				if err := core.RegisterSyncSubnetCurrentPeriodProto(s, req.Epoch, pubKey, assignment.Status); err != nil {
					return nil, err
				}
			}
			nextAssignment.IsSyncCommittee = assignment.IsSyncCommittee

			// Next epoch sync committee duty is assigned with next period sync committee only during
			// sync period epoch boundary (ie. EPOCHS_PER_SYNC_COMMITTEE_PERIOD - 1). Else wise
			// next epoch sync committee duty is the same as current epoch.
			nextEpoch := req.Epoch + 1
			currentEpoch := coreTime.CurrentEpoch(s)
			if slots.SyncCommitteePeriod(nextEpoch) > slots.SyncCommitteePeriod(currentEpoch) {
				nextAssignment.IsSyncCommittee, err = helpers.IsNextPeriodSyncCommittee(s, idx)
				if err != nil {
					return nil, status.Errorf(codes.Internal, "Could not determine next epoch sync committee: %v", err)
				}
				if nextAssignment.IsSyncCommittee {
					if err := core.RegisterSyncSubnetNextPeriodProto(s, req.Epoch, pubKey, nextAssignment.Status); err != nil {
						return nil, err
					}
				}
			}
		}

		validatorAssignments = append(validatorAssignments, assignment)
		nextValidatorAssignments = append(nextValidatorAssignments, nextAssignment)
	}
	return &ethpb.DutiesResponse{
		CurrentEpochDuties: validatorAssignments,
		NextEpochDuties:    nextValidatorAssignments,
	}, nil
}

// AssignValidatorToSubnet checks the status and pubkey of a particular validator
// to discern whether persistent subnets need to be registered for them.
func (vs *Server) AssignValidatorToSubnet(_ context.Context, req *ethpb.AssignValidatorToSubnetRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
