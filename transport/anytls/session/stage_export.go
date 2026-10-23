package session

import (
	"encoding/json"
	"time"
)

// StageEvidenceMaxResponseBytes bounds the entire JSON response body. The
// inner publication leaves room for its fixed-size envelope. No evidence is
// sent to the shared logger or its subscribers.
const StageEvidenceMaxResponseBytes = 64 * 1024
const stageEvidenceBodyLimit = StageEvidenceMaxResponseBytes - 1024
const StageEvidenceHistoryCapacity = 3

type stagePublication struct {
	raw      json.RawMessage // immutable after atomic publication
	captured time.Time
	sequence uint64
}

// No publication links to another publication. Each immutable view holds only
// these three bodies; a reader never returns the view or any mutable raw bytes.
type stagePublicationHistory struct {
	publications [StageEvidenceHistoryCapacity]*stagePublication // newest first
}

type StageEvidenceHistory struct {
	OldestSequence uint64
	LatestSequence uint64
	LatestAgeMS    float64
	Gap            string
}

type StageEvidenceSnapshot struct {
	Schema        int                   `json:"schema"`
	Kind          string                `json:"kind"`
	Availability  string                `json:"availability"`
	EvidenceEpoch *string               `json:"evidence_epoch"`
	Sequence      *uint64               `json:"sequence"`
	AgeMS         *float64              `json:"age_ms"`
	FailedExports uint64                `json:"failed_exports_total"`
	Snapshot      json.RawMessage       `json:"snapshot"`
	History       *StageEvidenceHistory `json:"-"` // bounded Unix HTTP metadata only
}

// ReadServerStageEvidence reads only a cached publication. It never collects,
// waits on a session/registry mutex, or creates an observer. Inactive includes
// both a disabled listener and no authenticated opt-in session yet; it is not
// evidence of zero active proxy sessions. Callers may mutate their returned
// bytes without modifying the publication seen by another request.
func ReadServerStageEvidence() StageEvidenceSnapshot {
	return serverStageHub.Load().readPublication()
}

// ReadServerStageEvidenceAfter is used only by the Unix cursor route. It reads
// one immutable history view, never collects or acquires proxy/session locks.
func ReadServerStageEvidenceAfter(epoch string, after uint64) StageEvidenceSnapshot {
	return serverStageHub.Load().readPublicationAfter(epoch, after)
}

func (h *stageHub) readPublicationAfter(epoch string, after uint64) StageEvidenceSnapshot {
	out := StageEvidenceSnapshot{Schema: 1, Kind: "anytls_stage_snapshot", Availability: "inactive"}
	if h == nil {
		return out
	}
	nonce := h.nonce
	out.EvidenceEpoch, out.FailedExports = &nonce, h.failedExports.Load()
	out.Availability = "awaiting_sample"
	view := h.history.Load()
	if view == nil || view.publications[0] == nil {
		return out
	}
	latest := view.publications[0]
	selected, oldest := latest, latest
	for _, publication := range view.publications {
		if publication != nil {
			oldest = publication
		}
	}
	gap := "none"
	if epoch != h.nonce {
		gap = "epoch_changed"
	} else if after > latest.sequence {
		gap = "cursor_ahead"
	} else if after < latest.sequence {
		for i := len(view.publications) - 1; i >= 0; i-- {
			publication := view.publications[i]
			if publication != nil && publication.sequence > after {
				selected = publication
				break
			}
		}
		if after < oldest.sequence && oldest.sequence-after > 1 {
			gap = "retention"
		} else if selected.sequence-after > 1 {
			gap = "publication"
		}
	}
	now := time.Now()
	sequence, age := selected.sequence, float64(now.Sub(selected.captured))/float64(time.Millisecond)
	out.Availability, out.Sequence, out.AgeMS = "ready", &sequence, &age
	out.Snapshot = append(json.RawMessage(nil), selected.raw...)
	out.History = &StageEvidenceHistory{oldest.sequence, latest.sequence,
		float64(now.Sub(latest.captured)) / float64(time.Millisecond), gap}
	return out
}

func (h *stageHub) readPublication() StageEvidenceSnapshot {
	out := StageEvidenceSnapshot{Schema: 1, Kind: "anytls_stage_snapshot", Availability: "inactive"}
	if h == nil {
		return out
	}
	epoch := h.nonce
	out.EvidenceEpoch = &epoch
	out.FailedExports = h.failedExports.Load()
	out.Availability = "awaiting_sample"
	p := h.latest.Load()
	if p == nil {
		return out
	}
	sequence := p.sequence
	age := float64(time.Since(p.captured)) / float64(time.Millisecond)
	out.Availability = "ready"
	out.Sequence, out.AgeMS = &sequence, &age
	out.Snapshot = append(json.RawMessage(nil), p.raw...)
	return out
}

// Called by the one bounded exporter, outside every observer/session mutex.
// One exporter is the sole writer. Retain at most three independent immutable
// bodies, plus the legacy latest pointer. Old reader views can finish safely;
// proxy operations never take a new lock or reference this history.
func (h *stageHub) publish(b stageBatch) {
	raw, err := json.Marshal(b)
	if len(raw) > stageEvidenceBodyLimit {
		b.PayloadLimited = true
		b.OmittedSessions = len(b.Sessions)
		b.OmittedSlow = len(b.SlowEvents)
		for _, event := range b.SlowEvents {
			for i, name := range evidenceStageNames {
				if event.Stage == name {
					b.OmittedSlowByClass[i]++
					break
				}
			}
		}
		b.Sessions, b.SlowEvents = nil, nil
		raw, err = json.Marshal(b)
	}
	if err != nil || len(raw) > stageEvidenceBodyLimit {
		h.failedExports.Add(1)
		return
	}
	publication := &stagePublication{raw: raw, captured: b.Captured, sequence: b.Sequence}
	view := &stagePublicationHistory{}
	view.publications[0] = publication
	if old := h.history.Load(); old != nil {
		copy(view.publications[1:], old.publications[:StageEvidenceHistoryCapacity-1])
	}
	h.history.Store(view)
	h.latest.Store(publication)
}
