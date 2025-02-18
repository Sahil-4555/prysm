package synccommittee

import (
	"strconv"

	"github.com/pkg/errors"
	"github.com/prysmaticlabs/prysm/v5/consensus-types/primitives"
	"github.com/prysmaticlabs/prysm/v5/container/queue"
	ethpb "github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1"
)

// To give two slots tolerance for objects that arrive earlier.
// This account for previous slot, current slot, two future slots.
const syncCommitteeMaxQueueSize = 4

// SaveSyncCommitteeContribution stores a sync committee contribution in a priority queue.
// The queue has a maximum size of 4 slots to handle:
// - Previous slot
// - Current slot
// - Two future slots (tolerance for early arrivals)
func (s *Store) SaveSyncCommitteeContribution(cont *ethpb.SyncCommitteeContribution) error {
	if cont == nil {
		return errNilContribution
	}

	s.contributionLock.Lock()
	defer s.contributionLock.Unlock()
	// PopByKey searches the queue for an item with the given key and removes it
	// from the queue if found. Returns nil if not found. This method must fix the
	// queue after removing any key.
	item, err := s.contributionCache.PopByKey(syncCommitteeKey(cont.Slot))
	if err != nil {
		return err
	}
	// CopySyncCommitteeContribution copies the provided sync committee contribution object.
	copied := ethpb.CopySyncCommitteeContribution(cont)

	// Contributions exist in the queue. Append instead of insert new.
	if item != nil {
		// Get existing contributions array
		contributions, ok := item.Value.([]*ethpb.SyncCommitteeContribution)
		if !ok {
			return errors.New("not typed []ethpb.SyncCommitteeContribution")
		}
		// Add new contribution to existing array
		contributions = append(contributions, copied)
		// Update metrics counter
		savedSyncCommitteeContributionTotal.Inc()
		// Store updated array back in cache
		return s.contributionCache.Push(&queue.Item{
			Key:      syncCommitteeKey(cont.Slot),
			Value:    contributions,
			Priority: int64(cont.Slot),
		})
	}

	// Contribution does not exist. Insert new.
	if err := s.contributionCache.Push(&queue.Item{
		Key:      syncCommitteeKey(cont.Slot),
		Value:    []*ethpb.SyncCommitteeContribution{copied},
		Priority: int64(cont.Slot),
	}); err != nil {
		return err
	}
	savedSyncCommitteeContributionTotal.Inc()

	// Maintain queue size limit by removing oldest item if needed
	if s.contributionCache.Len() > syncCommitteeMaxQueueSize {
		if _, err := s.contributionCache.Pop(); err != nil {
			return err
		}
	}

	return nil
}

// SyncCommitteeContributions returns sync committee contributions by slot from the priority queue.
// Upon retrieval, the contribution is removed from the queue.
func (s *Store) SyncCommitteeContributions(slot primitives.Slot) ([]*ethpb.SyncCommitteeContribution, error) {
	s.contributionLock.RLock()
	defer s.contributionLock.RUnlock()

	item := s.contributionCache.RetrieveByKey(syncCommitteeKey(slot))
	if item == nil {
		return []*ethpb.SyncCommitteeContribution{}, nil
	}

	contributions, ok := item.Value.([]*ethpb.SyncCommitteeContribution)
	if !ok {
		return nil, errors.New("not typed []ethpb.SyncCommitteeContribution")
	}

	return contributions, nil
}

func syncCommitteeKey(slot primitives.Slot) string {
	return strconv.FormatUint(uint64(slot), 10)
}
