//go:build linux

package anytls

import (
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func setOuterTCPWriteQueue(conn net.Conn) error {
	socket, ok := conn.(syscall.Conn)
	if !ok {
		return errors.New("outer connection has no raw TCP socket")
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		return err
	}
	if raw == nil {
		return errors.New("outer raw TCP socket unavailable")
	}
	var optionErr error
	if err = raw.Control(func(fd uintptr) {
		optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, outerTCPWriteLowWater)
	}); err != nil {
		return err
	}
	return optionErr
}
