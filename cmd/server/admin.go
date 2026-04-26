package main

// Admin API — lightweight management endpoints
// Secured with admin token, runs on a separate port

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Online session tracking
type OnlineSession struct {
	Username   string    `json:"username"`
	Group      string    `json:"group"`
	ClientIP   string    `json:"clientIP"`   // real client IP
	VPNAddr    string    `json:"vpnAddr"`    // assigned VPN IP
	RemoteAddr string    `json:"remoteAddr"` // TCP remote addr
	ConnTime   time.Time `json:"connTime"`
	BytesIn    int64     `json:"bytesIn"`
	BytesOut   int64     `json:"bytesOut"`
	DTLS       bool      `json:"dtls"`
}

var (
	onlineSessions sync.Map // vpnIP → *OnlineSession
	totalConns     atomic.Int64
	totalBytes     atomic.Int64
)

func RegisterOnline(vpnIP, username, group, clientIP, remoteAddr string) {
	onlineSessions.Store(vpnIP, &OnlineSession{
		Username:   username,
		Group:      group,
		ClientIP:   clientIP,
		VPNAddr:    vpnIP,
		RemoteAddr: remoteAddr,
		ConnTime:   time.Now(),
	})
	totalConns.Add(1)
}

func UnregisterOnline(vpnIP string) {
	onlineSessions.Delete(vpnIP)
}

func SetOnlineDTLS(vpnIP string, active bool) {
	val, ok := onlineSessions.Load(vpnIP)
	if ok {
		val.(*OnlineSession).DTLS = active
	}
}

func AddOnlineBytes(vpnIP string, in, out int64) {
	val, ok := onlineSessions.Load(vpnIP)
	if ok {
		sess := val.(*OnlineSession)
		atomic.AddInt64(&sess.BytesIn, in)
		atomic.AddInt64(&sess.BytesOut, out)
	}
	totalBytes.Add(in + out)
}

// Login failure tracking
type loginTracker struct {
	mu       sync.Mutex
	failures map[string]*failInfo // ip or user → failures
}

type failInfo struct {
	Count    int
	LastFail time.Time
	Locked   bool
}

var loginLock = &loginTracker{failures: make(map[string]*failInfo)}

const (
	maxLoginFails   = 5
	lockDuration    = 15 * time.Minute
)

func (lt *loginTracker) RecordFail(key string) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	fi, ok := lt.failures[key]
	if !ok {
		fi = &failInfo{}
		lt.failures[key] = fi
	}
	fi.Count++
	fi.LastFail = time.Now()
	if fi.Count >= maxLoginFails {
		fi.Locked = true
	}
}

func (lt *loginTracker) RecordSuccess(key string) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	delete(lt.failures, key)
}

func (lt *loginTracker) IsLocked(key string) bool {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	fi, ok := lt.failures[key]
	if !ok {
		return false
	}
	if fi.Locked && time.Since(fi.LastFail) > lockDuration {
		delete(lt.failures, key)
		return false
	}
	return fi.Locked
}

func (lt *loginTracker) GetLocked() []string {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	var locked []string
	for k, fi := range lt.failures {
		if fi.Locked && time.Since(fi.LastFail) <= lockDuration {
			locked = append(locked, k)
		}
	}
	return locked
}

func (lt *loginTracker) Unlock(key string) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	delete(lt.failures, key)
}

// Audit log
type AuditEntry struct {
	Time     time.Time `json:"time"`
	Username string    `json:"username"`
	Action   string    `json:"action"` // login, logout, auth_fail
	RemoteIP string    `json:"remoteIP"`
	Detail   string    `json:"detail,omitempty"`
}

var (
	auditLog   []AuditEntry
	auditMu    sync.Mutex
	maxAuditEntries = 10000
)

func AuditLog(username, action, remoteIP, detail string) {
	auditMu.Lock()
	defer auditMu.Unlock()
	auditLog = append(auditLog, AuditEntry{
		Time:     time.Now(),
		Username: username,
		Action:   action,
		RemoteIP: remoteIP,
		Detail:   detail,
	})
	if len(auditLog) > maxAuditEntries {
		auditLog = auditLog[len(auditLog)-maxAuditEntries:]
	}
	log.Printf("AUDIT: user=%s action=%s ip=%s %s", username, action, remoteIP, detail)
	dbAuditLog(username, action, remoteIP, detail)
}

// Admin HTTP server
func startAdminAPI(addr, token string) {
	if addr == "" || token == "" {
		return
	}

	mux := http.NewServeMux()

	// Auth middleware
	auth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+token {
				http.Error(w, "unauthorized", 401)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			next(w, r)
		}
	}

	// GET /api/online — list online users
	mux.HandleFunc("/api/online", auth(func(w http.ResponseWriter, r *http.Request) {
		var sessions []*OnlineSession
		onlineSessions.Range(func(key, val interface{}) bool {
			sessions = append(sessions, val.(*OnlineSession))
			return true
		})
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count":    len(sessions),
			"sessions": sessions,
		})
	}))

	// POST /api/kick?ip=10.99.0.2 — kick user
	mux.HandleFunc("/api/kick", auth(func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			http.Error(w, `{"error":"ip required"}`, 400)
			return
		}
		val, ok := onlineSessions.Load(ip)
		if !ok {
			http.Error(w, `{"error":"not found"}`, 404)
			return
		}
		sess := val.(*OnlineSession)
		AuditLog(sess.Username, "kicked", r.RemoteAddr, "vpn="+ip)
		UnregisterOnline(ip)
		json.NewEncoder(w).Encode(map[string]string{"status": "kicked", "ip": ip})
	}))

	// GET /api/stats — server stats
	mux.HandleFunc("/api/stats", auth(func(w http.ResponseWriter, r *http.Request) {
		count := 0
		onlineSessions.Range(func(_, _ interface{}) bool { count++; return true })
		json.NewEncoder(w).Encode(map[string]interface{}{
			"online":     count,
			"totalConns": totalConns.Load(),
			"totalBytes": totalBytes.Load(),
			"locked":     loginLock.GetLocked(),
		})
	}))

	// GET /api/audit — audit log
	mux.HandleFunc("/api/audit", auth(func(w http.ResponseWriter, r *http.Request) {
		auditMu.Lock()
		entries := make([]AuditEntry, len(auditLog))
		copy(entries, auditLog)
		auditMu.Unlock()
		// Return last 100
		if len(entries) > 100 {
			entries = entries[len(entries)-100:]
		}
		json.NewEncoder(w).Encode(entries)
	}))

	// POST /api/unlock?key=xxx — unlock locked user/IP
	mux.HandleFunc("/api/unlock", auth(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		loginLock.Unlock(key)
		json.NewEncoder(w).Encode(map[string]string{"status": "unlocked", "key": key})
	}))

	// GET /api/users — list users (DB mode)
	mux.HandleFunc("/api/users", auth(func(w http.ResponseWriter, r *http.Request) {
		if db == nil {
			http.Error(w, `{"error":"no database"}`, 400)
			return
		}
		switch r.Method {
		case "GET":
			users, err := dbListUsers()
			if err != nil { http.Error(w, err.Error(), 500); return }
			json.NewEncoder(w).Encode(users)
		case "POST":
			var u struct{ Username, Password, Group string }
			json.NewDecoder(r.Body).Decode(&u)
			if err := dbAddUser(u.Username, u.Password, u.Group); err != nil {
				http.Error(w, err.Error(), 500); return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "created", "username": u.Username})
		case "DELETE":
			u := r.URL.Query().Get("username")
			dbDelUser(u)
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "username": u})
		}
	}))

	// GET /api/audit/db — audit from database
	mux.HandleFunc("/api/audit/db", auth(func(w http.ResponseWriter, r *http.Request) {
		if db == nil { http.Error(w, `{"error":"no database"}`, 400); return }
		entries, _ := dbGetAuditLog(100)
		json.NewEncoder(w).Encode(entries)
	}))

	// POST /api/reload — reload users.json
	mux.HandleFunc("/api/reload", auth(func(w http.ResponseWriter, r *http.Request) {
		if cfg.UsersFile == "" {
			http.Error(w, `{"error":"no users file"}`, 400)
			return
		}
		if err := loadUsers(cfg.UsersFile); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "reloaded"})
	}))

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("Admin API listen failed: %v", err)
		return
	}
	log.Printf("Admin API on %s", addr)
	go http.Serve(ln, mux)
}
