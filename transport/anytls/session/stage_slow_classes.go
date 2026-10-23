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
	reserved  atomic.Int32
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

// Reservation is a fixed number of atomic operations, with no retry or wait.
// Count reserved-but-not-yet-sent events too, so a successful reservation can
// format outside the queue without blocking another proxy operation. A failed
// reservation may briefly hold capacity until its decrement, just as a producer
// and collector can observe different instants of the bounded queue.
func (h *stageHub) reserveSlow(stage int) (*stageSlowQueue, bool) {
	queue := &h.slow[stage]
	queue.attempted.Add(1)
	if queue.reserved.Add(1) <= int32(cap(queue.events)) {
		return queue, true
	}
	queue.reserved.Add(-1)
	queue.dropped.Add(1)
	h.lostSlow.Add(1)
	return nil, false
}

func (h *stageHub) commitSlow(queue *stageSlowQueue, event stageSlowEvent) {
	select {
	case queue.events <- event:
		queue.admitted.Add(1)
	default:
		// Preserve nonblocking operation even if future code violates the
		// reservation invariant. Release capacity and expose the loss.
		queue.reserved.Add(-1)
		queue.dropped.Add(1)
		// Preserve the existing total: queue-full losses across all classes.
		h.lostSlow.Add(1)
	}
}

func (h *stageHub) enqueueSlow(stage int, event stageSlowEvent) {
	if queue, ok := h.reserveSlow(stage); ok {
		h.commitSlow(queue, event)
	}
}

func (h *stageHub) collectSlow(batch *stageBatch) {
	for stage, capacity := range evidenceSlowClassCapacity {
		queue := &h.slow[stage]
		for i := 0; i < capacity; i++ {
			select {
			case event := <-queue.events:
				queue.reserved.Add(-1)
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
