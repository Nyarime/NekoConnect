package main

// Standard DTLS 1.2 for AnyConnect UDP acceleration
// AnyConnect negotiates DTLS via:
// 1. Client sends X-DTLS-Master-Secret in CONNECT request
// 2. Server responds with X-DTLS-Port, X-DTLS-CipherSuite
// 3. Client opens UDP to that port, does DTLS handshake using master secret as PSK
// 4. Data frames same format as CSTP (STF\x01 header)

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/songgao/water"
)

type DTLSServer struct {
	port     int
	cert     tls.Certificate
	sessions sync.Map // masterSecret(hex) → *DTLSSession
	listener net.Listener
}

type DTLSSession struct {
	MasterSecret string
	ClientIP     net.IP
	TUN          *water.Interface
	conn         net.Conn // DTLS conn once established
	mu           sync.Mutex
}

func NewDTLSServer(port int, cert tls.Certificate) *DTLSServer {
	return &DTLSServer{port: port, cert: cert}
}

func (s *DTLSServer) Start() error {
	addr := &net.UDPAddr{Port: s.port}

	config := &dtls.Config{
		Certificates:         []tls.Certificate{s.cert},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		ConnectContextMaker: func() (context.Context, func()) {
			return context.WithTimeout(context.Background(), 30*time.Second)
		},
	}

	listener, err := dtls.Listen("udp", addr, config)
	if err != nil {
		return fmt.Errorf("DTLS listen: %w", err)
	}
	s.listener = listener
	log.Printf("DTLS server on UDP :%d", s.port)

	go s.acceptLoop()
	return nil
}

func (s *DTLSServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Printf("DTLS accept: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *DTLSServer) handleConn(conn net.Conn) {
	defer conn.Close()

	// Read first DTLS data packet to identify session
	// AnyConnect sends CSTP-format frames over DTLS
	buf := make([]byte, 65536)
	for {
		conn.SetReadDeadline(time.Now().Add(40 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if n < 8 {
			continue
		}

		pktType := buf[6]
		dataLen := binary.BigEndian.Uint16(buf[4:6])

		switch pktType {
		case PktDATA:
			if int(dataLen)+8 <= n {
				// Find session by remote addr and write to TUN
				// For now, broadcast to all sessions
				s.sessions.Range(func(key, val interface{}) bool {
					sess := val.(*DTLSSession)
					if sess.TUN != nil {
						sess.TUN.Write(buf[8 : 8+int(dataLen)])
					}
					return false // stop at first match
				})
			}
		case PktDPD_REQ:
			resp := make([]byte, 8)
			copy(resp, plHeader)
			resp[6] = PktDPD_RESP
			conn.Write(resp)
		case PktKEEPALIVE:
			// no response
		case PktDISCONNECT:
			return
		}
	}
}

// RegisterSession maps a CSTP session to DTLS
func (s *DTLSServer) RegisterSession(masterSecret string, clientIP net.IP, tun *water.Interface) {
	s.sessions.Store(masterSecret[:32], &DTLSSession{
		MasterSecret: masterSecret,
		ClientIP:     clientIP,
		TUN:          tun,
	})
}

// UnregisterSession removes a DTLS session
func (s *DTLSServer) UnregisterSession(masterSecret string) {
	if len(masterSecret) >= 32 {
		s.sessions.Delete(masterSecret[:32])
	}
}

// WriteTo sends a packet to the DTLS client
func (s *DTLSServer) WriteTo(masterSecret string, packet []byte) error {
	val, ok := s.sessions.Load(masterSecret[:32])
	if !ok {
		return fmt.Errorf("no DTLS session")
	}
	sess := val.(*DTLSSession)
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.conn == nil {
		return fmt.Errorf("DTLS not connected")
	}

	frame := make([]byte, 8+len(packet))
	copy(frame, plHeader)
	binary.BigEndian.PutUint16(frame[4:6], uint16(len(packet)))
	frame[6] = PktDATA
	copy(frame[8:], packet)

	_, err := sess.conn.Write(frame)
	return err
}

// DTLSHeaders returns the X-DTLS-* headers for CSTP tunnel response
func DTLSHeaders(port int) string {
	return fmt.Sprintf("X-DTLS-Port: %d\r\n"+
		"X-DTLS-Keepalive: 20\r\n"+
		"X-DTLS-DPD: 30\r\n"+
		"X-DTLS-Rekey-Time: 86400\r\n"+
		"X-DTLS12-CipherSuite: ECDHE-RSA-AES256-GCM-SHA384\r\n"+
		"X-DTLS12-CipherSuite: ECDHE-RSA-AES128-GCM-SHA256\r\n"+
		"X-DTLS-CipherSuite: AES256-GCM-SHA384\r\n"+
		"X-DTLS-CipherSuite: AES128-GCM-SHA256\r\n",
		port)
}

// ParseMasterSecret decodes the hex master secret from client header
func ParseMasterSecret(hexStr string) ([]byte, error) {
	return hex.DecodeString(hexStr)
}
