package main

// DTLS UDP acceleration channel for NekoConnect
// AnyConnect uses CSTP (TLS over TCP) + DTLS (over UDP) for performance
// DTLS uses pre-shared master secret negotiated during CSTP setup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/songgao/water"
)

// DTLSSession represents an active DTLS data channel for a VPN client
type DTLSSession struct {
	ClientIP     net.IP
	MasterSecret []byte // shared with CSTP setup (X-DTLS-Master-Secret header)
	UDPAddr      *net.UDPAddr
	TUN          *water.Interface
	Cipher       cipher.AEAD
	LastSeen     time.Time
	mu           sync.Mutex
}

// DTLSManager handles all DTLS sessions on a UDP listener
type DTLSManager struct {
	conn     *net.UDPConn
	sessions sync.Map // masterSecret hex → *DTLSSession
}

// NewDTLSManager creates a UDP listener for DTLS data channels
func NewDTLSManager(addr string) (*DTLSManager, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	m := &DTLSManager{conn: conn}
	go m.readLoop()
	log.Printf("DTLS manager listening on %s (UDP)", addr)
	return m, nil
}

// RegisterSession adds a DTLS session for a CSTP-authenticated client
func (m *DTLSManager) RegisterSession(masterSecret []byte, clientIP net.IP, tun *water.Interface) {
	// Derive AEAD cipher from master secret (simplified: use first 32 bytes as AES key)
	if len(masterSecret) < 32 {
		// Pad if too short
		padded := make([]byte, 32)
		copy(padded, masterSecret)
		masterSecret = padded
	}
	block, _ := aes.NewCipher(masterSecret[:32])
	aead, _ := cipher.NewGCM(block)

	session := &DTLSSession{
		ClientIP:     clientIP,
		MasterSecret: masterSecret,
		TUN:          tun,
		Cipher:       aead,
		LastSeen:     time.Now(),
	}
	key := fmt.Sprintf("%x", masterSecret[:16])
	m.sessions.Store(key, session)
	log.Printf("DTLS session registered: %s (key=%s...)", clientIP, key[:8])
}

// readLoop handles incoming UDP packets from VPN clients
func (m *DTLSManager) readLoop() {
	buf := make([]byte, 65536)
	for {
		n, addr, err := m.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 16 {
			continue
		}

		// First 16 bytes: session identifier (first 16 bytes of master_secret hex prefix)
		// In real DTLS, this is part of the DTLS record header
		// Simplified: we use a session lookup table
		sessionKey := fmt.Sprintf("%x", buf[:16])

		val, ok := m.sessions.Load(sessionKey)
		if !ok {
			continue // unknown session
		}
		session := val.(*DTLSSession)
		session.mu.Lock()
		session.UDPAddr = addr
		session.LastSeen = time.Now()
		session.mu.Unlock()

		// Decrypt payload
		nonce := buf[16:28]
		ciphertext := buf[28:n]
		plaintext, err := session.Cipher.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			continue
		}

		// Write to TUN
		session.TUN.Write(plaintext)
	}
}

// SendToClient sends a packet from TUN to the DTLS client
func (s *DTLSSession) SendToClient(conn *net.UDPConn, packet []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.UDPAddr == nil {
		return fmt.Errorf("client not connected via DTLS yet")
	}

	// Build packet: [16 byte session ID][12 byte nonce][encrypted payload]
	out := make([]byte, 0, 16+12+len(packet)+16)
	out = append(out, s.MasterSecret[:16]...)

	nonce := make([]byte, 12)
	rand.Read(nonce)
	out = append(out, nonce...)

	ciphertext := s.Cipher.Seal(nil, nonce, packet, nil)
	out = append(out, ciphertext...)

	_, err := conn.WriteToUDP(out, s.UDPAddr)
	return err
}

// CleanupStale removes sessions with no traffic for 60+ seconds
func (m *DTLSManager) CleanupStale() {
	now := time.Now()
	m.sessions.Range(func(key, val interface{}) bool {
		s := val.(*DTLSSession)
		s.mu.Lock()
		stale := now.Sub(s.LastSeen) > 60*time.Second
		s.mu.Unlock()
		if stale {
			m.sessions.Delete(key)
		}
		return true
	})
}

// Conn returns the underlying UDP listener
func (m *DTLSManager) Conn() *net.UDPConn { return m.conn }

// Helper: encode uint16 BigEndian
func putBE16(b []byte, v uint16) {
	binary.BigEndian.PutUint16(b, v)
}
