package main

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

func emitMeasured(w io.Writer, id int, body []byte, ledger *OriginLedger) error {
	p, err := nowPoint()
	if err != nil {
		return err
	}
	ledger.ready(id, p) // Body and SHA were prepared before origin-ready.
	for off := 0; off < len(body); {
		end := off + 32768
		if end > len(body) {
			end = len(body)
		}
		for off < end {
			begin, e := nowPoint()
			if e != nil {
				return e
			}
			index := ledger.callBegin(id, begin, end-off)
			n, e := w.Write(body[off:end])
			finish, clockErr := nowPoint()
			errClass := ""
			if n < 0 || n > end-off {
				n = 0
				e = errors.New("invalid_write_count")
			}
			if e != nil || n == 0 {
				errClass = "origin_write"
			}
			if clockErr != nil {
				errClass = "clock"
			}
			ledger.callEnd(id, index, n, finish, errClass)
			off += n
			if errClass != "" {
				ledger.end(id, finish, errClass)
				return errors.New(errClass)
			}
		}
	}
	p, err = nowPoint()
	if err != nil {
		return err
	}
	ledger.end(id, p, "")
	return nil
}

func origin(dir string) error {
	var bodies [requestCount][]byte
	var sums [requestCount]string
	for id := range bodies {
		bodies[id] = make([]byte, payloadBytes(id))
		fill(bodies[id], 0, seedFor(id))
		sums[id] = digest(payloadBytes(id), seedFor(id))
	}
	l, err := net.Listen("tcp4", "127.0.0.1:19081")
	if err != nil {
		return err
	}
	defer l.Close()
	ledger := new(OriginLedger)
	var wg sync.WaitGroup
	var peersMu sync.Mutex
	peers := make([]net.Conn, 0, requestCount)
	var ioErrors, refs, protocolErrors atomic.Uint64
	controlErr := make(chan error, 1)
	controlDone := make(chan struct{})
	// No per-event disk IO: at most one explicit snapshot plus final result.
	go func() {
		defer close(controlDone)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		until := time.NewTimer(150 * time.Second)
		defer until.Stop()
		snapshotted := false
		for {
			select {
			case <-until.C:
				controlErr <- errors.New("origin_lifetime")
				_ = l.Close()
				return
			case <-ticker.C:
				if !snapshotted {
					if _, e := os.Stat(filepath.Join(dir, "origin-snapshot")); e == nil {
						snapshotted = true
						if e = save(filepath.Join(dir, "origin-proof.json"), ledger.snapshot()); e != nil {
							controlErr <- e
							_ = l.Close()
							return
						}
					}
				}
				if _, e := os.Stat(filepath.Join(dir, "stop")); e == nil {
					controlErr <- nil
					_ = l.Close()
					return
				}
			}
		}
	}()
	if err = save(filepath.Join(dir, "origin-ready.json"), map[string]any{"ready": true, "prepared_payload_bytes": bulkBytes + smallCount*smallBytes, "pid": os.Getpid(), "clock": "CLOCK_MONOTONIC", "utc": stamp()}); err != nil {
		return err
	}
	for {
		conn, e := l.Accept()
		if e != nil {
			break
		}
		peersMu.Lock()
		if len(peers) >= requestCount {
			peersMu.Unlock()
			_ = conn.Close()
			protocolErrors.Add(1)
			continue
		}
		peers = append(peers, conn)
		peersMu.Unlock()
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(140 * time.Second))
			var header [21]byte
			for {
				_, e := io.ReadFull(c, header[:])
				if e == io.EOF {
					return
				}
				if e != nil {
					ioErrors.Add(1)
					return
				}
				parsed, e := nowPoint()
				if e != nil {
					protocolErrors.Add(1)
					return
				}
				h, e := parseHeader(header[:])
				if e != nil {
					protocolErrors.Add(1)
					return
				}
				if h.Op == opReference {
					b := make([]byte, h.Bytes)
					fill(b, 0, h.ID)
					if e = writeAll(c, b); e != nil {
						ioErrors.Add(1)
						return
					}
					refs.Add(1)
					continue
				}
				id := int(h.ID)
				if e = ledger.begin(id, parsed, sums[id]); e != nil {
					protocolErrors.Add(1)
					return
				}
				if e = emitMeasured(c, id, bodies[id], ledger); e != nil {
					ioErrors.Add(1)
					return
				}
			}
		}(conn)
	}
	peersMu.Lock()
	for _, c := range peers {
		_ = c.Close()
	}
	peersMu.Unlock()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	joined := false
	select {
	case <-done:
		joined = true
	case <-time.After(2 * time.Second):
	}
	var endErr error
	select {
	case <-controlDone:
		endErr = <-controlErr
	case <-time.After(2 * time.Second):
		endErr = errors.New("origin_control_unfinished")
	}
	err = save(filepath.Join(dir, "origin-result.json"), map[string]any{"proof": ledger.snapshot(), "all_handlers_joined": joined,
		"reference_requests": refs.Load(), "io_errors_including_cleanup": ioErrors.Load(), "protocol_errors": protocolErrors.Load(),
		"control_normal_stop": endErr == nil, "utc": stamp()})
	if err != nil {
		return err
	}
	if !joined || endErr != nil {
		return errors.New("origin_shutdown")
	}
	return nil
}
