package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Actual CLOCK_MONOTONIC, shared across these network namespaces. UTC is display
// only. The runner must reject differing time namespaces before GO.
type Point struct {
	MonoNS int64  `json:"monotonic_ns"`
	UTC    string `json:"utc"`
}

func nowPoint() (Point, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return Point{}, err
	}
	return Point{MonoNS: ts.Nano(), UTC: stamp()}, nil
}
func sleepUntil(due int64) (Point, error) {
	for {
		p, err := nowPoint()
		if err != nil || p.MonoNS >= due {
			return p, err
		}
		time.Sleep(time.Duration(due - p.MonoNS))
	}
}

type WriterResult struct {
	Armed Point  `json:"armed"`
	Wake  Point  `json:"wake"`
	Begin Point  `json:"begin"`
	End   Point  `json:"end"`
	Error string `json:"error_class"`
}
type ReaderResult struct {
	ReadBegin Point  `json:"read_begin"`
	First     Point  `json:"first_byte"`
	Verified  Point  `json:"verified"`
	Finished  Point  `json:"finished"`
	Bytes     uint64 `json:"bytes"`
	SHA256    string `json:"sha256"`
	Error     string `json:"error_class"`
}

// Called in its own goroutine before GO, independent of request Write. The
// signal is immediately before the first Read, not proof of continuous OS
// scheduling. Gaps after reads can still include GC or host scheduling.
func drain(r io.Reader, n uint64, want string, armed chan<- Point) (out ReaderResult) {
	var err error
	out.ReadBegin, err = nowPoint()
	armed <- out.ReadBegin
	if err != nil {
		out.Error = "clock"
		return
	}
	h := sha256.New()
	var b [32768]byte
	for out.Bytes < n {
		k := uint64(len(b))
		if n-out.Bytes < k {
			k = n - out.Bytes
		}
		nr, readErr := r.Read(b[:k])
		if nr < 0 || nr > int(k) {
			out.Error = "invalid_read_count"
			break
		}
		if nr > 0 {
			if out.Bytes == 0 {
				out.First, err = nowPoint()
				if err != nil {
					out.Error = "clock"
					break
				}
			}
			_, _ = h.Write(b[:nr])
			out.Bytes += uint64(nr)
		}
		if out.Bytes == n {
			break
		}
		if readErr != nil {
			out.Error = "response_read"
			break
		}
		if nr == 0 {
			out.Error = "zero_read"
			break
		}
	}
	out.SHA256 = hex.EncodeToString(h.Sum(nil))
	if out.Error == "" && out.Bytes == n && out.SHA256 == want {
		out.Verified, err = nowPoint()
		if err != nil {
			out.Error = "clock"
		}
	} else if out.Error == "" {
		out.Error = "response_integrity"
	}
	out.Finished, err = nowPoint()
	if err != nil && out.Error == "" {
		out.Error = "clock"
	}
	return
}

const maxWriteCalls = 256

type WriteCall struct {
	Begin     Point  `json:"begin"`
	End       Point  `json:"end"`
	Requested int    `json:"requested_bytes"`
	Accepted  int    `json:"accepted_bytes"`
	Error     string `json:"error_class"`
}
type OriginRow struct {
	ID         int         `json:"id"`
	Parsed     Point       `json:"parsed"`
	Ready      Point       `json:"ready"`
	WriteBegin Point       `json:"write_begin"`
	WriteEnd   Point       `json:"write_end"`
	Bytes      uint64      `json:"accepted_bytes"`
	SHA256     string      `json:"expected_sha256"`
	Calls      []WriteCall `json:"write_calls"`
	Omitted    uint64      `json:"omitted_write_calls"`
	Error      string      `json:"error_class"`
}
type OriginLedger struct {
	mu         sync.Mutex
	rows       [requestCount]OriginRow
	present    [requestCount]bool
	duplicates uint64
	invalid    uint64
}

func (l *OriginLedger) begin(id int, p Point, sha string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if id < 0 || id >= requestCount || p.MonoNS <= 0 {
		l.invalid++
		return errors.New("origin_id")
	}
	if l.present[id] {
		l.duplicates++
		return errors.New("origin_duplicate")
	}
	l.present[id] = true
	l.rows[id] = OriginRow{ID: id, Parsed: p, SHA256: sha, Calls: make([]WriteCall, 0, maxWriteCalls)}
	return nil
}

// All updates are bounded copies; never hold the ledger mutex over socket IO.
func (l *OriginLedger) ready(id int, p Point) {
	l.mu.Lock()
	l.rows[id].Ready = p
	l.mu.Unlock()
}
func (l *OriginLedger) callBegin(id int, p Point, n int) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	r := &l.rows[id]
	if r.WriteBegin.MonoNS == 0 {
		r.WriteBegin = p
	}
	if len(r.Calls) == maxWriteCalls {
		r.Omitted++
		return -1
	}
	r.Calls = append(r.Calls, WriteCall{Begin: p, Requested: n})
	return len(r.Calls) - 1
}
func (l *OriginLedger) callEnd(id, index, n int, p Point, errClass string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r := &l.rows[id]
	if n > 0 {
		r.Bytes += uint64(n)
	}
	if index >= 0 {
		r.Calls[index].End = p
		r.Calls[index].Accepted = n
		r.Calls[index].Error = errClass
	}
	if errClass != "" {
		r.Error = errClass
	}
}
func (l *OriginLedger) end(id int, p Point, errClass string) {
	l.mu.Lock()
	l.rows[id].WriteEnd = p
	l.rows[id].Error = errClass
	l.mu.Unlock()
}
func (l *OriginLedger) snapshot() map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	rows := make([]OriginRow, 0, requestCount)
	for id, present := range l.present {
		if !present {
			continue
		}
		r := l.rows[id]
		r.Calls = append([]WriteCall{}, r.Calls...)
		rows = append(rows, r)
	}
	return map[string]any{"clock": "CLOCK_MONOTONIC", "capacity": requestCount, "rows": rows,
		"duplicates": l.duplicates, "invalid": l.invalid, "parsed_count": len(rows), "snapshot_utc": stamp()}
}
