package main

// DTLS 1.2 for AnyConnect/OpenConnect UDP acceleration
// Key insight from anylink: use pion/dtls SessionStore for session resumption
// Client sends X-DTLS-Master-Secret during CSTP, server uses it to resume DTLS

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
	"github.com/songgao/water"
)

// dtlsSessionMap maps DtlsSid → *DTLSSessionInfo
var dtlsSessionMap sync.Map

type DTLSSessionInfo struct {
	MasterSecret string
	DtlsSid      string
	ClientIP     net.IP
	TUN          *water.Interface
	mu           sync.RWMutex
	ready        chan struct{}
}

// sessionStore implements pion/dtls SessionStore interface
type sessionStore struct{}

func (s *sessionStore) Set(key []byte, session dtls.Session) error {
	return nil
}

func (s *sessionStore) Get(key []byte) (dtls.Session, error) {
	sid := hex.EncodeToString(key)
	val, ok := dtlsSessionMap.Load(sid)
	if !ok {
		return dtls.Session{}, errors.New("no session for DTLS SID")
	}
	info := val.(*DTLSSessionInfo)
	masterSecret, err := hex.DecodeString(info.MasterSecret)
	if err != nil {
		return dtls.Session{}, err
	}
	return dtls.Session{ID: key, Secret: masterSecret}, nil
}

func (s *sessionStore) Del(key []byte) error {
	return nil
}

func RegisterDTLSSession(dtlsSid, masterSecret string, clientIP net.IP, tun *water.Interface) {
	val, loaded := dtlsSessionMap.LoadOrStore(dtlsSid, &DTLSSessionInfo{
		MasterSecret: masterSecret,
		DtlsSid:      dtlsSid,
		ClientIP:     clientIP,
		TUN:          tun,
		ready:        make(chan struct{}),
	})
	if loaded {
		// Update existing session with TUN
		info := val.(*DTLSSessionInfo)
		info.mu.Lock()
		info.ClientIP = clientIP
		info.TUN = tun
		info.mu.Unlock()
		select {
		case <-info.ready:
		default:
			close(info.ready)
		}
	} else if tun != nil {
		info := val.(*DTLSSessionInfo)
		close(info.ready)
	}
}

func UnregisterDTLSSession(dtlsSid string) {
	dtlsSessionMap.Delete(dtlsSid)
}

func LookupDTLSSession(dtlsSid string) *DTLSSessionInfo {
	val, ok := dtlsSessionMap.Load(dtlsSid)
	if !ok { return nil }
	return val.(*DTLSSessionInfo)
}

func startDTLSServer(port int) error {
	// Generate fresh RSA key for DTLS (separate from TLS cert, like anylink does)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("RSA keygen: %w", err)
	}
	certificate, err := selfsign.SelfSign(priv)
	if err != nil {
		return fmt.Errorf("self-sign: %w", err)
	}

	config := &dtls.Config{
		Certificates:         []tls.Certificate{certificate},
		ExtendedMasterSecret: dtls.DisableExtendedMasterSecret,
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		SessionStore: &sessionStore{},
		MTU:          1400,
		ConnectContextMaker: func() (context.Context, func()) {
			return context.WithTimeout(context.Background(), 5*time.Second)
		},
	}

	addr := &net.UDPAddr{Port: port}
	ln, err := dtls.Listen("udp", addr, config)
	if err != nil {
		return fmt.Errorf("DTLS listen: %w", err)
	}

	log.Printf("DTLS server on UDP :%d", port)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Printf("DTLS accept: %v", err)
				continue
			}
			go handleDTLSConn(conn)
		}
	}()
	return nil
}

func handleDTLSConn(conn net.Conn) {
	defer conn.Close()

	dc, ok := conn.(*dtls.Conn)
	if !ok {
		return
	}

	// Get session ID to find our session
	sid := hex.EncodeToString(dc.ConnectionState().SessionID)
	info := LookupDTLSSession(sid)
	if info == nil {
		log.Printf("DTLS: unknown session %s", sid[:16])
		return
	}

	log.Printf("DTLS connected: %s (waiting for TUN...)", conn.RemoteAddr())

	// Wait for TUN to be ready (set by CSTP handler)
	select {
	case <-info.ready:
	case <-time.After(10 * time.Second):
		log.Printf("DTLS: TUN not ready after 10s")
		return
	}

	info.mu.RLock()
	tun := info.TUN
	clientIP := info.ClientIP
	info.mu.RUnlock()
	if tun == nil {
		log.Printf("DTLS: TUN still nil")
		return
	}

	log.Printf("DTLS active: %s → %s", conn.RemoteAddr(), clientIP)

	// Bidirectional: DTLS ↔ TUN
	dead := 35 * time.Second
	buf := make([]byte, 65536)

	// TUN → DTLS writer
	go func() {
		tbuf := make([]byte, 65536)
		for {
			n, err := tun.Read(tbuf)
			if err != nil {
				return
			}
			frame := make([]byte, 1+n)
			frame[0] = PktDATA
			copy(frame[1:], tbuf[:n])
			conn.Write(frame)
		}
	}()

	// DTLS → TUN reader
	for {
		conn.SetReadDeadline(time.Now().Add(dead))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if n < 1 {
			continue
		}

		switch buf[0] {
		case PktDATA:
			if n > 1 {
				tun.Write(buf[1:n])
			}
		case PktDPD_REQ:
			resp := []byte{PktDPD_RESP}
			conn.Write(resp)
		case PktKEEPALIVE:
			// nothing
		case PktDISCONNECT:
			return
		}
	}
}

// RandomHex generates a random hex string of n bytes
func RandomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// DTLSHeaders returns the DTLS headers for CSTP response
func DTLSResponseHeaders(port int, dtlsSid string) string {
	return fmt.Sprintf("X-DTLS-Port: %d\r\n"+
		"X-DTLS-Session-ID: %s\r\n"+
		"X-DTLS-DPD: 30\r\n"+
		"X-DTLS-Keepalive: 20\r\n"+
		"X-DTLS-Rekey-Time: 86400\r\n"+
		"X-DTLS-Rekey-Method: new-tunnel\r\n"+
		"X-DTLS12-CipherSuite: ECDHE-RSA-AES256-GCM-SHA384\r\n",
		port, dtlsSid)
}

// Unused import guard
var _ = binary.BigEndian
