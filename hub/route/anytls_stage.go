package route

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/metacubex/mihomo/transport/anytls/session"
)

// This extra route is mounted only by startUnix, never the TCP, TLS or named
// pipe controller. It inherits the Unix management socket's file permissions.
func unixRouter(isDebug bool, dohServer string, cors Cors) *chi.Mux {
	r := router(isDebug, "", dohServer, cors)
	r.Get("/diagnostics/anytls-stage", stageEvidenceHandler(session.ReadServerStageEvidence))
	r.Get("/diagnostics/anytls-stage/history", stageEvidenceHistoryHandler(session.ReadServerStageEvidenceAfter))
	return r
}

func stageEvidenceHandler(read func() session.StageEvidenceSnapshot) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// read returns a copy of one immutable, fixed-size publication. A slow
		// controller client can block its HTTP handler, never the observer.
		body, err := json.Marshal(read())
		if err != nil || len(body) > session.StageEvidenceMaxResponseBytes {
			http.Error(w, "diagnostic snapshot unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-PCS-Stage-History", "1")
		w.Write(body)
	}
}

var stageCursorEpoch = regexp.MustCompile(`^[0-9a-f]{16}$`)
var stageCursorSequence = regexp.MustCompile(`^(0|[1-9][0-9]{0,19})$`)

func stageEvidenceHistoryHandler(read func(string, uint64) session.StageEvidenceSnapshot) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Bound the raw query before parsing, including duplicate/unknown keys.
		if len(r.URL.RawQuery) > 128 {
			http.Error(w, "invalid diagnostic cursor", http.StatusBadRequest)
			return
		}
		query, queryErr := url.ParseQuery(r.URL.RawQuery)
		if queryErr != nil || len(query) != 2 || len(query["epoch"]) != 1 || len(query["after"]) != 1 ||
			!stageCursorEpoch.MatchString(query.Get("epoch")) || !stageCursorSequence.MatchString(query.Get("after")) {
			http.Error(w, "invalid diagnostic cursor", http.StatusBadRequest)
			return
		}
		after, err := strconv.ParseUint(query.Get("after"), 10, 64)
		if err != nil {
			http.Error(w, "invalid diagnostic cursor", http.StatusBadRequest)
			return
		}
		snapshot := read(query.Get("epoch"), after)
		body, err := json.Marshal(snapshot)
		if err != nil || len(body) > session.StageEvidenceMaxResponseBytes {
			http.Error(w, "diagnostic snapshot unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-PCS-Stage-History", "1")
		if history := snapshot.History; history != nil {
			w.Header().Set("X-PCS-Stage-Oldest", strconv.FormatUint(history.OldestSequence, 10))
			w.Header().Set("X-PCS-Stage-Latest", strconv.FormatUint(history.LatestSequence, 10))
			w.Header().Set("X-PCS-Stage-Latest-Age-Ms", strconv.FormatFloat(history.LatestAgeMS, 'f', 3, 64))
			w.Header().Set("X-PCS-Stage-Gap", history.Gap)
		}
		w.Write(body)
	}
}
