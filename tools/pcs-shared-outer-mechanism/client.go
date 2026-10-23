package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/metacubex/mihomo/transport/anytls/session"
)

type ClientRow struct {
	ID           int          `json:"id"`
	Outer        int          `json:"outer"`
	Role         string       `json:"role"`
	DueNS        int64        `json:"due_monotonic_ns"`
	Writer       WriterResult `json:"writer"`
	Reader       ReaderResult `json:"reader"`
	WriterJoined bool         `json:"writer_joined"`
	ReaderJoined bool         `json:"reader_joined"`
}
type writeMessage struct {
	ID     int
	Result WriterResult
}
type readMessage struct {
	ID     int
	Result ReaderResult
}

func client(dir, ca, password string, bulkOuter int) error {
	if bulkOuter != 0 && bulkOuter != 1 {
		return errors.New("bulk_outer")
	}
	setupDeadline := time.Now().Add(35 * time.Second)
	var outers [2]*Outer
	closeOuters := func() {
		// Close raw first to release native writer waits before Session.Close.
		for _, o := range outers {
			if o != nil {
				_ = o.raw.Close()
			}
		}
		for _, o := range outers {
			if o != nil {
				_ = o.session.Close()
			}
		}
	}
	defer closeOuters()
	var streams [requestCount]*session.Stream
	var expected [requestCount]string
	for id := range expected {
		expected[id] = digest(payloadBytes(id), seedFor(id))
	}
	for ordinal := range outers {
		o, err := makeOuter(ca, password, setupDeadline)
		if err != nil {
			return err
		}
		outers[ordinal] = o
		st, err := prime(o, ordinal, setupDeadline)
		if err != nil {
			return err
		}
		streams[ordinal] = st
		if string(o.pad.Load().RawScheme) != scheme {
			return errors.New("padding_not_negotiated")
		}
	}
	jobs := make([]int, 0, requestCount-2)
	for id := 2; id < requestCount; id++ {
		jobs = append(jobs, id)
	}
	if err := setupWorkers(jobs, func(id int) error {
		st, err := prime(outers[outerFor(id, bulkOuter)], id, setupDeadline)
		if err == nil {
			streams[id] = st
		}
		return err
	}); err != nil {
		return err
	}
	seen := make(map[*session.Stream]bool)
	for _, st := range streams {
		if st == nil || seen[st] {
			return errors.New("stream_identity")
		}
		seen[st] = true
	}
	// Real 4096-byte no-bulk reference on each outer. These two fixed reference
	// values are descriptive, not cherry-picked per-ID subtraction baselines.
	var reference [2]map[string]any
	for ordinal := range outers {
		begin, err := nowPoint()
		if err != nil {
			return err
		}
		seed := uint32(120000 + ordinal)
		if err = request(streams[ordinal], Header{Op: opReference, Bytes: smallBytes, ID: seed}); err != nil {
			return err
		}
		sum, err := receiveSetup(streams[ordinal], smallBytes)
		finish, clockErr := nowPoint()
		if err != nil || clockErr != nil || sum != digest(smallBytes, seed) {
			return errors.New("reference_integrity")
		}
		reference[ordinal] = map[string]any{"outer": ordinal, "begin": begin, "verified": finish, "bytes": smallBytes, "sha256": sum}
	}
	idle := make([]float64, 0, 20)
	for i := 0; i < 20; i++ {
		t := time.Now()
		seed := uint32(130000 + i)
		if err := request(streams[bulkID], Header{Op: opReference, Bytes: 1, ID: seed}); err != nil {
			return err
		}
		sum, err := receiveSetup(streams[bulkID], 1)
		if err != nil || sum != digest(1, seed) {
			return errors.New("idle_echo")
		}
		idle = append(idle, float64(time.Since(t))/float64(time.Millisecond))
	}
	if time.Now().After(setupDeadline) {
		return errors.New("readiness_deadline")
	}
	// Both reader and writer workers exist before READY. No per-outer
	// application lock, lane or semaphore is accessed after GO.
	readArmed := make(chan Point, requestCount)
	writeArmed := make(chan Point, requestCount)
	reads := make(chan readMessage, requestCount)
	writes := make(chan writeMessage, requestCount)
	goSignal := make(chan struct{})
	var base Point
	ports := [2]int{}
	for i, o := range outers {
		ports[i] = o.raw.LocalAddr().(*net.TCPAddr).Port
		_ = o.raw.SetDeadline(time.Now().Add(120 * time.Second))
	}
	for id, st := range streams {
		_ = st.SetDeadline(time.Now().Add(120 * time.Second))
		go func(id int, st *session.Stream) {
			reads <- readMessage{id, drain(st, payloadBytes(id), expected[id], readArmed)}
		}(id, st)
		go func(id int, st *session.Stream) {
			out := WriterResult{}
			out.Armed, _ = nowPoint()
			writeArmed <- out.Armed
			<-goSignal // Channel publication synchronizes the immutable base.
			if base.MonoNS == 0 {
				out.Error = "go_aborted"
				writes <- writeMessage{id, out}
				return
			}
			var err error
			out.Wake, err = sleepUntil(base.MonoNS + int64(dueOffset(id)))
			if err == nil {
				out.Begin, err = nowPoint()
			}
			if err == nil {
				err = request(st, Header{Op: opMeasured, Bytes: payloadBytes(id), ID: uint32(id)})
			}
			out.End, _ = nowPoint()
			if err != nil {
				out.Error = "request_write_or_clock"
			}
			writes <- writeMessage{id, out}
		}(id, st)
	}
	goPublished := false
	defer func() {
		if !goPublished {
			close(goSignal)
		}
	}()
	for i := 0; i < requestCount; i++ {
		readPoint, writePoint := <-readArmed, <-writeArmed
		if readPoint.MonoNS <= 0 || writePoint.MonoNS <= 0 {
			return errors.New("worker_arm_clock")
		}
	}
	select {
	case early := <-reads:
		_ = save(filepath.Join(dir, "pre-go-read-result.json"), early)
		return errors.New("response_completed_before_request_GO")
	default:
	}
	if err := save(filepath.Join(dir, "client-ready.json"), map[string]any{"ready": true, "outer_sessions": 2, "streams": requestCount,
		"readers_armed": requestCount, "writers_armed": requestCount, "unique_streams": len(seen), "setup_workers": 8,
		"measured_application_queue": false, "tls_verified": 2, "padding_verified": 2, "bulk_outer": bulkOuter,
		"synthetic_local_ports": ports, "references": reference, "idle_echo_ms": idle, "pid": os.Getpid(), "utc": stamp()}); err != nil {
		return err
	}
	if err := waitFile(filepath.Join(dir, "go"), time.Now().Add(40*time.Second)); err != nil {
		return err
	}
	// Disk start record is deliberately after workload: no JSON/file sync on
	// the request scheduling path. Controller GO file brackets the handshake.
	until := time.Now().Add(deadline)
	for _, o := range outers {
		_ = o.raw.SetDeadline(until)
	}
	for _, st := range streams {
		_ = st.SetDeadline(until)
	}
	var err error
	base, err = nowPoint()
	if err != nil {
		return err
	}
	close(goSignal)
	goPublished = true
	rows := make([]ClientRow, requestCount)
	for id := range rows {
		rows[id] = ClientRow{ID: id, Outer: outerFor(id, bulkOuter), Role: roleFor(id, bulkOuter), DueNS: base.MonoNS + int64(dueOffset(id))}
	}
	remaining := 2 * requestCount
	timer := time.NewTimer(deadline)
	defer timer.Stop()
	timedOut := false
	for remaining > 0 && !timedOut {
		select {
		case m := <-writes:
			rows[m.ID].Writer = m.Result
			rows[m.ID].WriterJoined = true
			remaining--
		case m := <-reads:
			rows[m.ID].Reader = m.Result
			rows[m.ID].ReaderJoined = true
			remaining--
		case <-timer.C:
			timedOut = true
		}
	}
	if timedOut {
		closeOuters()
		drainTimer := time.NewTimer(2 * time.Second)
		for remaining > 0 {
			select {
			case m := <-writes:
				rows[m.ID].Writer = m.Result
				rows[m.ID].WriterJoined = true
				remaining--
			case m := <-reads:
				rows[m.ID].Reader = m.Result
				rows[m.ID].ReaderJoined = true
				remaining--
			case <-drainTimer.C:
				goto finished
			}
		}
		drainTimer.Stop()
	}
finished:
	end, clockErr := nowPoint()
	ok := !timedOut && remaining == 0 && clockErr == nil
	for _, row := range rows {
		if row.Writer.Error != "" || row.Reader.Error != "" || row.Reader.Bytes != payloadBytes(row.ID) || row.Reader.SHA256 != expected[row.ID] {
			ok = false
		}
	}
	if err = save(filepath.Join(dir, "client-result.json"), map[string]any{"schema": 1, "ok": ok, "clock": "CLOCK_MONOTONIC", "bulk_outer": bulkOuter,
		"start": base, "end": end, "deadline_seconds": 45, "timed_out": timedOut, "unjoined_workers": remaining,
		"population": requestCount, "expected_application_bytes": bulkBytes + smallCount*smallBytes, "rows": rows}); err != nil {
		return err
	}
	// Read-only final TCP capture may use this bounded hold. It is outside the
	// workload endpoint; absence of finish is a runner failure, never success.
	if err = waitFile(filepath.Join(dir, "finish"), time.Now().Add(8*time.Second)); err != nil {
		return err
	}
	if !ok {
		return errors.New("measured_outcome")
	}
	return nil
}
