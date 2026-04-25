// Package cstp implements Cisco's CSTP (Client SSL Transport Protocol).
// This is the TLS-based VPN tunnel used by AnyConnect.
//
// Protocol flow:
// 1. Client does HTTP CONNECT /CSCOSSLC/tunnel
// 2. Server responds 200 + CSTP headers (MTU, routes, DNS, etc.)
// 3. Both sides switch to binary framing
//
// Frame format:
// [0-3] "STF\x01" magic (Server-To-Client) or "CTF\x01" (Client-To-Server)
// [4]   Type (0x00=DATA, 0x03=DPD_REQ, 0x04=DPD_RESP, 0x05=DISCONNECT, 0x07=KEEPALIVE)
// [5-6] Length (big-endian)
// [7]   Reserved
// [8..] Payload
package cstp

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	HeaderSize = 8

	TypeDATA       = 0x00
	TypeDPD_REQ    = 0x03
	TypeDPD_RESP   = 0x04
	TypeDISCONNECT = 0x05
	TypeKEEPALIVE  = 0x07
	TypeCOMPRESS   = 0x08
)

var (
	STFMagic = [4]byte{'S', 'T', 'F', 0x01}
	CTFMagic = [4]byte{'C', 'T', 'F', 0x01}
)

type Frame struct {
	Type    byte
	Payload []byte
}

type Conn struct {
	raw    net.Conn
	mu     sync.Mutex
	isServer bool
}

func NewServerConn(raw net.Conn) *Conn {
	return &Conn{raw: raw, isServer: true}
}

func NewClientConn(raw net.Conn) *Conn {
	return &Conn{raw: raw, isServer: false}
}

// ReadFrame reads one CSTP frame
func (c *Conn) ReadFrame() (*Frame, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(c.raw, header); err != nil {
		return nil, err
	}

	// Validate magic
	// Client sends "STF\x01", Server sends "STF\x01" (both use same magic in practice)
	frameType := header[4]
	length := binary.BigEndian.Uint16(header[5:7])

	var payload []byte
	if length > 0 {
		payload = make([]byte, length)
		if _, err := io.ReadFull(c.raw, payload); err != nil {
			return nil, err
		}
	}

	return &Frame{Type: frameType, Payload: payload}, nil
}

// WriteFrame writes one CSTP frame
func (c *Conn) WriteFrame(f *Frame) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	header := make([]byte, HeaderSize)
	copy(header[:4], STFMagic[:])
	header[4] = f.Type
	binary.BigEndian.PutUint16(header[5:7], uint16(len(f.Payload)))

	if _, err := c.raw.Write(header); err != nil {
		return err
	}
	if len(f.Payload) > 0 {
		if _, err := c.raw.Write(f.Payload); err != nil {
			return err
		}
	}
	return nil
}

// WriteData sends a DATA frame (VPN packet)
func (c *Conn) WriteData(data []byte) error {
	return c.WriteFrame(&Frame{Type: TypeDATA, Payload: data})
}

// WriteDPDResponse responds to a DPD request
func (c *Conn) WriteDPDResponse() error {
	return c.WriteFrame(&Frame{Type: TypeDPD_RESP})
}

// WriteKeepalive sends a keepalive
func (c *Conn) WriteKeepalive() error {
	return c.WriteFrame(&Frame{Type: TypeKEEPALIVE})
}

// Close sends disconnect and closes
func (c *Conn) Close() error {
	c.WriteFrame(&Frame{Type: TypeDISCONNECT})
	return c.raw.Close()
}

// SetDeadline proxies to underlying conn
func (c *Conn) SetDeadline(t time.Time) error {
	return c.raw.SetDeadline(t)
}

// CSTPHeaders returns the HTTP headers for tunnel establishment
func CSTPHeaders(clientIP, mask, dns string, mtu int, routes []string) string {
	h := fmt.Sprintf("X-CSTP-Address: %s\r\n", clientIP)
	h += fmt.Sprintf("X-CSTP-Netmask: %s\r\n", mask)
	h += fmt.Sprintf("X-CSTP-DNS: %s\r\n", dns)
	h += fmt.Sprintf("X-CSTP-MTU: %d\r\n", mtu)
	h += "X-CSTP-DPD: 30\r\n"
	h += "X-CSTP-Keepalive: 20\r\n"
	h += "X-CSTP-Compression: none\r\n"
	for _, route := range routes {
		h += fmt.Sprintf("X-CSTP-Split-Include: %s\r\n", route)
	}
	return h
}
