package anytls

import (
	"net"
	"sync"

	"github.com/metacubex/mihomo/log"
)

// This only limits unsent outer TCP data. It does not bound all SendQ bytes,
// change the congestion controller or create more network capacity.
const outerTCPWriteLowWater = 64 * 1024

// A blocked logging sink must not hold Accept. One process-wide report owns
// at most one asynchronous logger and captures no connection or error data.
type outerQueueWarning struct {
	once sync.Once
	emit func()
}

func (w *outerQueueWarning) report() {
	w.once.Do(func() { go w.emit() })
}

var outerWriteQueueWarning = outerQueueWarning{emit: func() {
	log.Warnln("[AnyTLS] outer TCP write-queue option unavailable; requested backpressure may not be active")
}}

type outerWriteQueueListener struct {
	net.Listener
	warning *outerQueueWarning
}

func wrapOuterWriteQueue(inner net.Listener, enabled bool) net.Listener {
	if !enabled {
		return inner
	}
	return &outerWriteQueueListener{Listener: inner, warning: &outerWriteQueueWarning}
}

func (l *outerWriteQueueListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return conn, err
	}
	// Return the original accepted connection, including on unsupported systems.
	// TLS wrapping, authentication, deadlines, Close and cookie unwrapping retain
	// their existing path. No fd is duplicated or retained by this operation.
	if err := setOuterTCPWriteQueue(conn); err != nil {
		l.warning.report()
	}
	return conn, nil
}
