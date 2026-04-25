package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Session struct {
	Cookie    string
	Username  string
	ClientIP  string
	CreatedAt time.Time
}

type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	password string
}

func NewManager(password string) *Manager {
	return &Manager{
		sessions: make(map[string]*Session),
		password: password,
	}
}

// Authenticate handles AnyConnect XML auth flow
func (m *Manager) Authenticate(r *http.Request) (string, error) {
	// AnyConnect sends XML auth with username/password
	// For simplicity, just check password
	body := make([]byte, 4096)
	n, _ := r.Body.Read(body)
	bodyStr := string(body[:n])

	// Extract password from XML
	if !strings.Contains(bodyStr, m.password) {
		return "", fmt.Errorf("auth failed")
	}

	// Generate session cookie
	cookieBytes := make([]byte, 32)
	rand.Read(cookieBytes)
	cookie := hex.EncodeToString(cookieBytes)

	m.mu.Lock()
	m.sessions[cookie] = &Session{
		Cookie:    cookie,
		CreatedAt: time.Now(),
	}
	m.mu.Unlock()

	return cookie, nil
}

// ValidateSession checks if a session cookie is valid
func (m *Manager) ValidateSession(cookie string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[cookie]
	if !ok {
		return false
	}
	return time.Since(s.CreatedAt) < 24*time.Hour
}

// AnyConnectXMLResponse returns the auth response XML
func AnyConnectXMLResponse(cookie, serverCert string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete">
<auth id="success">
<title>SSL VPN Service</title>
<message>Welcome</message>
</auth>
<session-token>%s</session-token>
<config>
<vpn-base-config>
<server-cert-hash>%s</server-cert-hash>
</vpn-base-config>
</config>
</config-auth>`, cookie, serverCert)
}
