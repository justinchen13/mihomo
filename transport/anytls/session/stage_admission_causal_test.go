package session

import (
	"testing"
	"time"
)

// This file uses only the production 68b13 API/fields. Copy it unchanged to
// that baseline for a negative control; compilation failure is not evidence.
// No socket, route fixture, sleep, or real-time scheduling assumption is used.
func TestStageAdmissionPreservesSlowWriterDuringAuthChurn(t *testing.T) {
	h := testStageHub(t)
	var handles []*stageHandle
	defer func() {
		for _, handle := range handles {
			handle.close()
		}
	}()
	cookie := "abcd"
	for i := 0; i < evidenceSessions; i++ {
		handles = append(handles, h.attach(&cookie))
	}
	original := handles[0]
	op := original.beginWrite(cmdPSH, 32775)
	original.acquire(&op)
	op.acquired = time.Now().Add(-200 * time.Millisecond)
	slot := &h.slots[original.slot]
	slot.mu.Lock()
	slot.owner.started = op.acquired
	slot.ownerTLS = op.acquired
	slot.mu.Unlock()
	for i := 0; i < evidenceSessions; i++ {
		handles = append(handles, h.attach(nil))
	}
	original.finishWrite(&op, nil)
	snapshot := original.snapshot(time.Now())
	batch := h.collect(time.Now())
	if snapshot.Status != "active" || snapshot.Metrics[stageWriterOwned].Count != 1 || batch.LostCompletions != 0 {
		t.Fatalf("slow writer evicted before completion: status=%s completed=%d lost=%d", snapshot.Status, snapshot.Metrics[stageWriterOwned].Count, batch.LostCompletions)
	}
	if snapshot.SocketCookie == nil || *snapshot.SocketCookie != cookie || batch.Tracked != 32 || batch.Untracked != 32 {
		t.Fatal("cookie or bounded population accounting changed")
	}
	found := false
	for _, event := range batch.SlowEvents {
		if event.Session == snapshot.Session && event.Stage == "writer_owned" {
			found = true
		}
	}
	if !found {
		t.Fatal("retained slow writer has no completion event")
	}
}
