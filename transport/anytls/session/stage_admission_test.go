package session

import (
	"sync"
	"testing"
	"time"
)

func TestStageAdmissionPreferenceBoundaries(t *testing.T) {
	now := time.Unix(123, 0)
	for _, age := range []time.Duration{-time.Nanosecond, 0, evidenceSlowThreshold - time.Nanosecond, evidenceSlowThreshold, evidenceSlowThreshold + time.Nanosecond} {
		slot := stageSlot{owner: stageWaiter{used: true, started: now.Add(-age)}}
		want := age >= evidenceSlowThreshold
		if slot.protectsSlowWrite(now) != want {
			t.Fatalf("owner threshold: age=%v", age)
		}
		slot.owner = stageWaiter{}
		slot.waiters[31] = stageWaiter{used: true, started: now.Add(-age)}
		if slot.protectsSlowWrite(now) != want {
			t.Fatalf("waiter threshold: age=%v", age)
		}
	}
	for _, stage := range []int{stageReadHeader, stageReadBody, stagePipeWrite} {
		slot := stageSlot{readStage: stage, read: stageWaiter{used: true, started: now.Add(-time.Hour)}}
		if slot.protectsSlowWrite(now) {
			t.Fatalf("read stage %d silently treated as slow writer", stage)
		}
	}
}

func TestStageAdmissionFreeFirstAndAllSlowRotation(t *testing.T) {
	h := testStageHub(t)
	var handles []*stageHandle
	defer func() {
		for _, handle := range handles {
			handle.close()
		}
	}()
	mark := func(handle *stageHandle) {
		slot := &h.slots[handle.slot]
		slot.mu.Lock()
		slot.owner = stageWaiter{used: true, started: time.Now().Add(-time.Second)}
		slot.mu.Unlock()
	}
	for i := 0; i < evidenceSessions; i++ {
		handle := h.attach(nil)
		handles = append(handles, handle)
		mark(handle)
	}
	handles[17].close()
	free := h.attach(nil)
	handles = append(handles, free)
	if free.slot != 17 || h.evicted.Load() != 0 {
		t.Fatal("free slot must win over all protected live slots")
	}
	mark(free)
	seen := make(map[int]bool)
	for i := 0; i < evidenceSessions; i++ {
		want := h.next
		handle := h.attach(nil)
		handles = append(handles, handle)
		if handle.slot != want || seen[handle.slot] {
			t.Fatal("all-slow fallback stopped rotating fairly")
		}
		seen[handle.slot] = true
		mark(handle)
	}
	batch := h.collect(time.Now())
	if len(seen) != 32 || batch.Tracked != 32 || batch.Evicted != 32 || batch.Admission != evidenceAdmissionPolicy {
		t.Fatal("all-slow capacity or policy mismatch")
	}
}

// Intended for targeted race validation: admissions, generation-checked DATA
// observations, close and snapshots retain the single h.mu -> slot.mu order.
// There is no network or protocol-policy action in this fixture.
func TestStageAdmissionConcurrentLifecycle(t *testing.T) {
	h := testStageHub(t)
	var handles []*stageHandle
	for i := 0; i < evidenceSessions; i++ {
		handles = append(handles, h.attach(nil))
	}
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		handle := handles[i]
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 64; j++ {
				op := handle.beginWrite(cmdPSH, 32)
				handle.acquire(&op)
				handle.finishWrite(&op, nil)
			}
		}()
	}
	for i := 0; i < 64; i++ {
		handles = append(handles, h.attach(nil))
		batch := h.collect(time.Now())
		if batch.Tracked > 32 || len(batch.Sessions) > 64 || batch.Untracked < 0 {
			t.Fatal("registry escaped fixed bounds")
		}
	}
	workers.Wait()
	for _, handle := range handles {
		handle.close()
	}
	if batch := h.collect(time.Now()); batch.Live != 0 || batch.Tracked != 0 {
		t.Fatal("closed contexts retained as live")
	}
}
