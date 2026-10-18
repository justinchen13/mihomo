package session

import "time"

const evidenceAdmissionPolicy = "bounded_slow_write_rotation_not_population_sample"

// Caller holds this slot's mutex. A long header/body read alone is not a slow
// writer and does not receive write-context preference. This is a selection
// policy, not a judgement that either type of read is healthy or faulty.
func (s *stageSlot) protectsSlowWrite(now time.Time) bool {
	if s.owner.used && now.Sub(s.owner.started) >= evidenceSlowThreshold {
		return true
	}
	for _, waiter := range s.waiters {
		if waiter.used && now.Sub(waiter.started) >= evidenceSlowThreshold {
			return true
		}
	}
	return false
}

// Caller holds h.mu. Return exactly one locked slot; the caller must unlock it.
// The free-first scan and at most one extra fixed-size scan preserve the lock
// order h.mu -> slot.mu used by close/collect. DATA never takes h.mu. No lock is
// held while waiting for I/O, publishing JSON, or writing diagnostics.
func (h *stageHub) admissionSlotLocked() (int, *stageSlot) {
	for i := 0; i < evidenceSessions; i++ {
		index := (h.next + i) % evidenceSessions
		slot := &h.slots[index]
		slot.mu.Lock()
		if !slot.live {
			return index, slot
		}
		slot.mu.Unlock()
	}
	for i := 0; i < evidenceSessions; i++ {
		index := (h.next + i) % evidenceSessions
		slot := &h.slots[index]
		slot.mu.Lock()
		if !slot.protectsSlowWrite(time.Now()) {
			return index, slot
		}
		slot.mu.Unlock()
	}
	// All slots contain slow writers: preserve bounded rotating admission.
	// Completion loss remains explicit; never pin all slots indefinitely or
	// block authentication until a writer makes progress.
	index := h.next
	slot := &h.slots[index]
	slot.mu.Lock()
	return index, slot
}
