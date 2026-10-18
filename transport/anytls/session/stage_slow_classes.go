package session

import (
	"sort"
	"sync/atomic"
)

const evidenceSlowPolicy = "fixed_stage_budgets_v1"

// Sum remains evidenceSlowEvents (32). Idle header reads remain observable but
// cannot consume the capacity reserved for other stages. These queues neither
// block proxy operations nor share a global write-path mutex.
var evidenceSlowClassCapacity = [evidenceStageCount]int{8, 4, 8, 2, 6, 4}

type stageSlowQueue struct {
	events    chan stageSlowEvent
	attempted atomic.Uint64
	admitted  atomic.Uint64
	dropped   atomic.Uint64
	dequeued  atomic.Uint64
}

type stageSlowQueueCounters struct {
	Capacity  int    `json:"capacity"`
	Attempted uint64 `json:"attempted"`
	Admitted  uint64 `json:"admitted"`
	Dropped   uint64 `json:"dropped"`
	Dequeued  uint64 `json:"dequeued"`
}

func (h *stageHub) enqueueSlow(stage int, event stageSlowEvent) {
	queue := &h.slow[stage]
	queue.attempted.Add(1)
	select {
	case queue.events <- event:
		queue.admitted.Add(1)
	default:
		queue.dropped.Add(1)
		// Preserve the existing total: queue-full losses across all classes.
		h.lostSlow.Add(1)
	}
}

func (h *stageHub) collectSlow(batch *stageBatch) {
	for stage, capacity := range evidenceSlowClassCapacity {
		queue := &h.slow[stage]
		for i := 0; i < capacity; i++ {
			select {
			case event := <-queue.events:
				queue.dequeued.Add(1)
				batch.SlowEvents = append(batch.SlowEvents, event)
			default:
				i = capacity
			}
		}
		// This is a bounded, non-atomic snapshot. A concurrent enqueue may be
		// between its attempted/send/admitted operations. Dequeued means removed
		// from the queue, not delivered to a consumer; export losses stay separate.
		batch.SlowQueueStats[stage] = stageSlowQueueCounters{
			Capacity: capacity, Attempted: queue.attempted.Load(),
			Admitted: queue.admitted.Load(), Dropped: queue.dropped.Load(),
			Dequeued: queue.dequeued.Load(),
		}
	}
	// Preserve completion-time order inside this publication, including ties.
	// Across publications a delayed producer can still enqueue an older event;
	// publication sequence is not a global event-order promise.
	sort.SliceStable(batch.SlowEvents, func(i, j int) bool {
		return batch.SlowEvents[i].completed.Before(batch.SlowEvents[j].completed)
	})
	batch.LostSlow = h.lostSlow.Load()
}
