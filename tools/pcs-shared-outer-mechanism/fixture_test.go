package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func TestFixedPopulationAndDue(t *testing.T) {
	for _, bulkOuter := range []int{0, 1} {
		counts := [2]int{}
		for id := 0; id < smallCount; id++ {
			counts[outerFor(id, bulkOuter)]++
			if dueOffset(id) != time.Second+time.Duration(id/2)*500*time.Millisecond {
				t.Fatal("due")
			}
			if roleFor(id, bulkOuter) == "bulk" {
				t.Fatal("role")
			}
		}
		if counts != [2]int{16, 16} || outerFor(bulkID, bulkOuter) != bulkOuter || dueOffset(bulkID) != 0 {
			t.Fatal("population")
		}
	}
	if smallCount*smallBytes+bulkBytes != 6422528 || deadline != 45*time.Second {
		t.Fatal("bytes/deadline")
	}
}

func TestHeaderPopulationAndReservedFields(t *testing.T) {
	for id := 0; id < requestCount; id++ {
		var b bytes.Buffer
		if err := request(&b, Header{opMeasured, payloadBytes(id), uint32(id)}); err != nil {
			t.Fatal(err)
		}
		h, err := parseHeader(b.Bytes())
		if err != nil || int(h.ID) != id {
			t.Fatal("roundtrip")
		}
		bad := append([]byte{}, b.Bytes()...)
		bad[20] = 1
		if _, err = parseHeader(bad); err == nil {
			t.Fatal("phase accepted")
		}
	}
	for _, h := range []Header{{opMeasured, smallBytes, requestCount}, {opMeasured, bulkBytes, 0}, {opReference, 17, 100000}, {opReference, 1, 1}} {
		if request(io.Discard, h) == nil {
			t.Fatal("invalid request accepted")
		}
	}
	var b [21]byte
	b[0] = opMeasured
	binary.BigEndian.PutUint64(b[1:9], smallBytes)
	b[12] = 1
	if _, err := parseHeader(b[:]); err == nil {
		t.Fatal("duration accepted")
	}
}

func TestOriginLedgerBoundedUniqueAndSnapshot(t *testing.T) {
	l := new(OriginLedger)
	if err := l.begin(0, Point{MonoNS: 1, UTC: "synthetic"}, "sum"); err != nil {
		t.Fatal(err)
	}
	l.ready(0, Point{MonoNS: 2})
	for i := 0; i < maxWriteCalls+1; i++ {
		j := l.callBegin(0, Point{MonoNS: int64(3 + i)}, 1)
		l.callEnd(0, j, 1, Point{MonoNS: int64(4 + i)}, "")
	}
	if l.begin(0, Point{MonoNS: 100}, "new") == nil || l.begin(requestCount, Point{MonoNS: 100}, "x") == nil {
		t.Fatal("identity")
	}
	x := l.snapshot()
	r := x["rows"].([]OriginRow)[0]
	if len(r.Calls) != maxWriteCalls || r.Omitted != 1 || r.Bytes != maxWriteCalls+1 || x["duplicates"] != uint64(1) || x["invalid"] != uint64(1) {
		t.Fatal("bound")
	}
	r.Calls[0].Accepted = 999
	if l.snapshot()["rows"].([]OriginRow)[0].Calls[0].Accepted != 1 {
		t.Fatal("snapshot alias")
	}
}

func TestOriginLedgerConcurrent(t *testing.T) {
	l := new(OriginLedger)
	var wg sync.WaitGroup
	for id := 0; id < requestCount; id++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			if e := l.begin(id, Point{MonoNS: int64(id + 1)}, "sha"); e != nil {
				t.Error(e)
			}
		}(id)
	}
	wg.Wait()
	if l.snapshot()["parsed_count"] != requestCount {
		t.Fatal("lost ID")
	}
}

type gatedReader struct {
	entered chan struct{}
	release chan struct{}
	data    []byte
	once    sync.Once
}

func (r *gatedReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.entered) })
	<-r.release
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func TestReadersArmedAndIndependentOfRequestWriter(t *testing.T) {
	// No sockets or sleeps. Two readers enter Read without any request-writer
	// completion. Release the second while the first is still blocked.
	newReader := func(seed uint32) *gatedReader {
		b := make([]byte, smallBytes)
		fill(b, 0, seed)
		return &gatedReader{make(chan struct{}), make(chan struct{}), b, sync.Once{}}
	}
	a, b := newReader(2000), newReader(2001)
	armed := make(chan Point, 2)
	ra := make(chan ReaderResult, 1)
	rb := make(chan ReaderResult, 1)
	go func() { ra <- drain(a, smallBytes, digest(smallBytes, 2000), armed) }()
	go func() { rb <- drain(b, smallBytes, digest(smallBytes, 2001), armed) }()
	select {
	case <-a.entered:
	case <-time.After(time.Second):
		t.Fatal("first reader not armed")
	}
	select {
	case <-b.entered:
	case <-time.After(time.Second):
		t.Fatal("reader serialized")
	}
	close(b.release)
	select {
	case r := <-rb:
		if r.Error != "" || r.Verified.MonoNS <= 0 {
			t.Fatal("second read")
		}
	case <-time.After(time.Second):
		t.Fatal("second blocked by first")
	}
	close(a.release)
	if r := <-ra; r.Error != "" {
		t.Fatal(r.Error)
	}
}

func TestLegacyReadAfterWriteCannotSatisfyPreGOReadiness(t *testing.T) {
	// Deterministic structural negative control: a legacy worker waits for
	// request Write to return before calling response Read. No real IO/sleep.
	writeEntered := make(chan struct{})
	returnFromWrite := make(chan struct{})
	readEntered := make(chan struct{})
	go func() { close(writeEntered); <-returnFromWrite; close(readEntered) }()
	<-writeEntered
	select {
	case <-readEntered:
		t.Fatal("legacy unexpectedly has a reader before Write returns")
	default: // The old path fails the new required reader-ready condition.
	}
	close(returnFromWrite)
	<-readEntered
}

func TestPartialReadRetainsFirstByteAndBytes(t *testing.T) {
	b := make([]byte, 10)
	fill(b, 0, 2000)
	r := drain(bytes.NewReader(b), smallBytes, digest(smallBytes, 2000), make(chan Point, 1))
	if r.Bytes != 10 || r.First.MonoNS <= 0 || r.Verified.MonoNS != 0 || r.Error == "" {
		t.Fatal("partial proof lost")
	}
}

type partialFailWriter struct{ n int }

func (w *partialFailWriter) Write(b []byte) (int, error) {
	if w.n == 0 {
		w.n++
		return 11, errors.New("synthetic")
	}
	return 0, io.ErrClosedPipe
}
func TestOriginWriteFailurePreservesPartial(t *testing.T) {
	l := new(OriginLedger)
	p, _ := nowPoint()
	if err := l.begin(0, p, digest(smallBytes, 2000)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, smallBytes)
	fill(b, 0, 2000)
	if emitMeasured(&partialFailWriter{}, 0, b, l) == nil {
		t.Fatal("expected failure")
	}
	r := l.snapshot()["rows"].([]OriginRow)[0]
	if r.Bytes != 11 || r.Error != "origin_write" || len(r.Calls) != 1 || r.Calls[0].Accepted != 11 {
		t.Fatal("partial write lost")
	}
}

func TestFrozenBulkTraceFitsBoundWithoutOmission(t *testing.T) {
	l := new(OriginLedger)
	p, err := nowPoint()
	if err != nil {
		t.Fatal(err)
	}
	if err = l.begin(bulkID, p, digest(bulkBytes, seedFor(bulkID))); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, bulkBytes)
	if err = emitMeasured(io.Discard, bulkID, body, l); err != nil {
		t.Fatal(err)
	}
	r := l.snapshot()["rows"].([]OriginRow)[0]
	if len(r.Calls) != 192 || r.Omitted != 0 || r.Bytes != bulkBytes {
		t.Fatal("frozen bulk trace truncated")
	}
}
