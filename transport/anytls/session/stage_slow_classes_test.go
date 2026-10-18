package session

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/anytls/padding"
	utls "github.com/metacubex/utls"
)

// This causal fixture also compiles against the original shared-queue baseline:
// header reads fill it, making every following useful-stage event disappear.
func TestStageSlowHeaderFloodCannotConsumeOtherClasses(t *testing.T) {
	h := testStageHub(t)
	e := h.attach(nil)
	defer e.close()
	for i := 0; i < 64; i++ {
		op := e.beginRead(stageReadHeader, cmdPSH, 7)
		op.started = time.Now().Add(-200 * time.Millisecond)
		e.finishRead(op, nil)
	}
	for _, stage := range []int{stageReadBody, stagePipeWrite} {
		op := e.beginRead(stage, cmdPSH, 1024)
		op.started = time.Now().Add(-200 * time.Millisecond)
		e.finishRead(op, nil)
	}
	batch := h.collect(time.Now())
	counts := make(map[string]int)
	for _, event := range batch.SlowEvents {
		counts[event.Stage]++
	}
	if counts["read_header"] != 2 || counts["read_body"] != 1 || counts["pipe_write"] != 1 {
		t.Fatalf("header flood consumed other-stage evidence: %v", counts)
	}
}

// Uses the existing real TLS/padding fixture, including a blocked DATA write,
// queued FIN, exact application payload, and bounded connection teardown.
func TestStageSlowHeaderFloodPreservesRealTLSStages(t *testing.T) {
	for _, version := range []uint16{utls.VersionTLS12, utls.VersionTLS13} {
		t.Run(hexUint(uint64(version)), func(t *testing.T) {
			writer, reader, wire := realTLSPair(t, version, true)
			var factory atomic.Pointer[padding.PaddingFactory]
			padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &factory)
			s := NewServerSession(writer, nil, &factory)
			h := testStageHub(t)
			s.evidence = h.attach(nil)
			defer s.Close()
			for i := 0; i < 64; i++ {
				op := s.evidence.beginRead(stageReadHeader, cmdPSH, 7)
				op.started = time.Now().Add(-200 * time.Millisecond)
				s.evidence.finishRead(op, nil)
			}
			payload := bytes.Repeat([]byte{1, 3, 5, 7}, 1024)
			received := make(chan frameResult, 1)
			go func() { received <- readAcceptedFrames(reader, 2) }()
			wire.enabled.Store(true)
			dataDone, finDone := make(chan error, 1), make(chan error, 1)
			go func() { _, err := s.writeDataFrame(1, payload); dataDone <- err }()
			<-wire.entered
			go func() { _, err := s.writeControlFrame(newFrame(cmdFIN, 3)); finDone <- err }()
			waitStage(t, s.evidence, "tls_write", "writer_wait")
			// The writer gate establishes blocking; this wait only crosses the
			// already fixed 100ms slow-event threshold, not a scheduling guess.
			time.Sleep(120 * time.Millisecond)
			awaitWrite(t, dataDone)
			awaitWrite(t, finDone)
			frames := <-received
			if frames.err != nil || len(frames.frames) != 2 || !bytes.Equal(frames.frames[0].payload, payload) || frames.frames[1].command != cmdFIN {
				t.Fatal("TLS/frame integrity")
			}
			batch := h.collect(time.Now())
			counts := make(map[string]int)
			for _, event := range batch.SlowEvents {
				counts[event.Stage]++
			}
			if counts["read_header"] != 2 || counts["tls_write"] == 0 || counts["writer_wait"] == 0 || counts["writer_owned"] == 0 || len(batch.SlowEvents) > evidenceSlowEvents {
				t.Fatalf("header flood hid TLS stages: %v", counts)
			}
		})
	}
}

func TestStageSlowClassesBoundedAndQuiescentAccounting(t *testing.T) {
	h := testStageHub(t)
	start := time.Now()
	var wg sync.WaitGroup
	for stage, capacity := range evidenceSlowClassCapacity {
		stage, capacity := stage, capacity
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < capacity+5; i++ {
				h.enqueueSlow(stage, stageSlowEvent{Stage: evidenceStageNames[stage], completed: start.Add(time.Duration(100-stage-i) * time.Millisecond)})
			}
		}()
	}
	wg.Wait()
	batch := h.collect(time.Now())
	if len(batch.SlowEvents) != evidenceSlowEvents || batch.LostSlow != 30 {
		t.Fatal("queue total or loss total changed")
	}
	for stage, capacity := range evidenceSlowClassCapacity {
		c := batch.SlowQueueStats[stage]
		if c.Capacity != capacity || c.Attempted != uint64(capacity+5) || c.Admitted != uint64(capacity) || c.Dropped != 5 || c.Dequeued != uint64(capacity) {
			t.Fatalf("class %d accounting: %+v", stage, c)
		}
	}
	for i := 1; i < len(batch.SlowEvents); i++ {
		if batch.SlowEvents[i].completed.Before(batch.SlowEvents[i-1].completed) {
			t.Fatal("completion-time merge order")
		}
	}
	next := h.collect(time.Now())
	if len(next.SlowEvents) != 0 || next.Sequence != batch.Sequence+1 || next.LostSlow != batch.LostSlow {
		t.Fatal("collection replay or counter reset")
	}
}

func TestStageSlowClassesPayloadOmissionsSeparateFromQueueDrops(t *testing.T) {
	h := testStageHub(t)
	for stage := range evidenceSlowClassCapacity {
		h.enqueueSlow(stage, stageSlowEvent{Stage: evidenceStageNames[stage]})
	}
	batch := h.collect(time.Now())
	batch.Sessions = []stageSnapshot{{Session: strings.Repeat("f", StageEvidenceMaxResponseBytes)}}
	h.publish(batch)
	var got stageBatch
	if err := json.Unmarshal(h.readPublication().Snapshot, &got); err != nil {
		t.Fatal(err)
	}
	if got.Schema != 2 || !got.PayloadLimited || got.OmittedSlow != evidenceStageCount || got.LostSlow != 0 {
		t.Fatal("omission/drop conflation")
	}
	for stage := range evidenceSlowClassCapacity {
		if got.OmittedSlowByClass[stage] != 1 || got.SlowQueueStats[stage].Dropped != 0 || got.SlowQueueStats[stage].Dequeued != 1 {
			t.Fatal("class omission lost")
		}
	}
}
