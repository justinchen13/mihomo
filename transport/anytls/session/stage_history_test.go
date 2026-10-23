package session

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestStageHistoryRetentionEpochAndCallerCopies(t *testing.T) {
	var absent *stageHub
	if absent.readPublicationAfter("0123456789abcdef", 1).Availability != "inactive" {
		t.Fatal("inactive")
	}
	h := testStageHub(t)
	if h.readPublicationAfter(h.nonce, 0).Availability != "awaiting_sample" {
		t.Fatal("awaiting")
	}
	for i := 0; i < 5; i++ {
		h.publish(h.collect(time.Now()))
	}
	out := h.readPublicationAfter(h.nonce, 1)
	if *out.Sequence != 3 || out.History.OldestSequence != 3 || out.History.LatestSequence != 5 || out.History.Gap != "retention" {
		t.Fatal("retention not explicit")
	}
	original := string(out.Snapshot)
	out.Snapshot[0] = '!'
	out.History.LatestSequence = 999
	again := h.readPublicationAfter(h.nonce, 1)
	if string(again.Snapshot) != original || again.History.LatestSequence != 5 {
		t.Fatal("mutable history escaped")
	}
	for _, test := range []struct {
		epoch    string
		after    uint64
		sequence uint64
		gap      string
	}{
		{h.nonce, 4, 5, "none"}, {h.nonce, 5, 5, "none"},
		{h.nonce, math.MaxUint64, 5, "cursor_ahead"}, {"other-epoch", 99, 5, "epoch_changed"},
	} {
		read := h.readPublicationAfter(test.epoch, test.after)
		if *read.Sequence != test.sequence || read.History.Gap != test.gap {
			t.Fatalf("cursor result: %+v", test)
		}
	}
	encoded, err := json.Marshal(again)
	var fields map[string]json.RawMessage
	if err != nil || json.Unmarshal(encoded, &fields) != nil || len(fields) != 8 || fields["History"] != nil || fields["history"] != nil {
		t.Fatal("legacy envelope shape changed")
	}
}

func TestStageHistoryExportFailureDoesNotFabricatePublication(t *testing.T) {
	h := testStageHub(t)
	h.publish(h.collect(time.Now()))
	failed := h.collect(time.Now())
	failed.ExportAgeMS = math.NaN()
	h.publish(failed)
	h.publish(h.collect(time.Now()))
	out := h.readPublicationAfter(h.nonce, 1)
	if *out.Sequence != 3 || out.FailedExports != 1 || out.History.Gap != "publication" || out.History.OldestSequence != 1 {
		t.Fatal("failed publication hidden or misclassified")
	}
}

func TestStageHistoryConcurrentReadersUseOneImmutableView(t *testing.T) {
	h := testStageHub(t)
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for j := 0; j < 200; j++ {
				out := h.readPublicationAfter(h.nonce, 0)
				if out.Availability != "ready" {
					continue
				}
				if !json.Valid(out.Snapshot) || out.History == nil || *out.Sequence < out.History.OldestSequence || *out.Sequence > out.History.LatestSequence {
					t.Error("torn view")
				}
				encoded, err := json.Marshal(out)
				if err != nil || len(encoded) > StageEvidenceMaxResponseBytes {
					t.Error("response budget")
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		h.publish(h.collect(time.Now()))
	}
	readers.Wait()
	view := h.history.Load()
	if len(view.publications) != 3 || view.publications[0].sequence != 200 || view.publications[2].sequence != 198 {
		t.Fatal("fixed retention")
	}
}

func TestStageHistoryConsumerFixtures(t *testing.T) {
	h := testStageHub(t)
	cookie := "1234"
	e := h.attach(&cookie)
	defer e.close()
	publish := func(bytes int) {
		op := e.beginRead(stageReadBody, cmdPSH, bytes)
		op.started = time.Now().Add(-150 * time.Millisecond)
		e.finishRead(op, nil)
		h.publish(h.collect(time.Now()))
	}
	publish(101)
	first := h.readPublication()
	publish(202)
	publish(303)
	fixtures := map[string]StageEvidenceSnapshot{"legacy1": first, "history2": h.readPublicationAfter(h.nonce, 1), "history3": h.readPublicationAfter(h.nonce, 2)}
	for name, out := range fixtures {
		body, err := json.Marshal(out)
		if err != nil || !json.Valid(body) || len(body) > StageEvidenceMaxResponseBytes {
			t.Fatal("fixture body")
		}
		headers := map[string]string{"X-PCS-Stage-History": "1"}
		if meta := out.History; meta != nil {
			headers["X-PCS-Stage-Oldest"] = strconv.FormatUint(meta.OldestSequence, 10)
			headers["X-PCS-Stage-Latest"] = strconv.FormatUint(meta.LatestSequence, 10)
			headers["X-PCS-Stage-Latest-Age-Ms"] = strconv.FormatFloat(meta.LatestAgeMS, 'f', 3, 64)
			headers["X-PCS-Stage-Gap"] = meta.Gap
		}
		if directory := os.Getenv("PCS_STAGE_HISTORY_FIXTURES"); directory != "" {
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, name+".body.json"), body, 0600); err != nil {
				t.Fatal(err)
			}
			metadata, err := json.Marshal(headers)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, name+".headers.json"), metadata, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}
