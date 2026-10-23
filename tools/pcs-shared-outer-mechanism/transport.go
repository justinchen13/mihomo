// Test-only; handshake and setup adapted from the frozen F2 fixture.
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/transport/anytls/padding"
	"github.com/metacubex/mihomo/transport/anytls/session"
	M "github.com/metacubex/sing/common/metadata"
)

type Outer struct {
	session *session.Session
	raw     *tls.Conn
	pad     *atomic.Pointer[padding.PaddingFactory]
	setupMu sync.Mutex // OpenStream/buffering mutation only, before GO.
}

func makeOuter(cafile, password string, deadline time.Time) (o *Outer, err error) {
	pem, err := os.ReadFile(cafile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("fixture CA")
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.IPv4(198, 51, 100, 2)}},
		"tcp4", "192.0.2.1:7443", &tls.Config{RootCAs: roots, ServerName: name, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
	if err != nil {
		return nil, err
	}
	good := false
	defer func() {
		if !good {
			conn.Close()
		}
	}()
	local, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok || !local.IP.Equal(net.IPv4(198, 51, 100, 2)) || local.Port <= 0 || len(conn.ConnectionState().VerifiedChains) == 0 {
		return nil, errors.New("fixture TLS/source verification")
	}
	_ = conn.SetDeadline(deadline)
	sum := sha256.Sum256([]byte(password))
	auth := append(sum[:], 0, 64)
	auth = append(auth, make([]byte, 64)...)
	if err = writeAll(conn, auth); err != nil {
		return nil, err
	}
	pad := new(atomic.Pointer[padding.PaddingFactory])
	if !padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, pad) {
		return nil, errors.New("padding")
	}
	s := session.NewClientSession(conn, pad)
	s.Run()
	good = true
	return &Outer{session: s, raw: conn, pad: pad}, nil
}

func prime(o *Outer, ordinal int, deadline time.Time) (*session.Stream, error) {
	// Native OpenStream mutates buffering outside connLock. Serialize setup
	// OpenStream + address + initial request, never the later response read.
	o.setupMu.Lock()
	st, err := o.session.OpenStream()
	if err == nil {
		_ = st.SetDeadline(deadline)
		err = M.SocksaddrSerializer.WriteAddrPort(st, M.ParseSocksaddr("127.0.0.1:19081"))
	}
	if err == nil {
		err = request(st, Header{Op: opReference, Bytes: 1, ID: uint32(100000 + ordinal)})
	}
	o.setupMu.Unlock()
	if err != nil {
		return nil, err
	}
	got, err := receiveSetup(st, 1)
	if err != nil || got != digest(1, uint32(100000+ordinal)) {
		return nil, errors.New("prime integrity")
	}
	return st, nil
}
