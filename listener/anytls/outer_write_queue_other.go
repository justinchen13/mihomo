//go:build !linux

package anytls

import (
	"errors"
	"net"
)

func setOuterTCPWriteQueue(net.Conn) error {
	return errors.New("outer TCP write-queue option unsupported on this platform")
}
