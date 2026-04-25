package main

// NekoConnect — AnyConnect-compatible VPN server
// Based on anylink (github.com/bjdgyc/anylink) protocol implementation
// + NekoPass-Core Reality TLS stealth

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// CSTP packet types (matches Cisco AnyConnect protocol)
const (
	PktDATA       = 0x00
	PktDPD_REQ    = 0x03
	PktDPD_RESP   = 0x04
	PktDISCONNECT = 0x05
	PktKEEPALIVE  = 0x07
	PktCOMPRESS   = 0x08
)

var plHeader = []byte{'S', 'T', 'F', 1, 0, 0, 0, 0}

// Config
var cfg struct {
	Listen   string
	SNI      string
	Password string
	Pool     string
	DNS      string
	MTU      int
	CertFile string
	KeyFile  string
}

// Session
type Session struct {
	Token    string
	Username string
	IP       net.IP
	Created  time.Time
}

var (
	sessions   = make(map[string]*Session)
	sessionsMu sync.RWMutex
	ipPool     *IPPool
)

func main() {
	flag.StringVar(&cfg.Listen, "listen", ":443", "Listen address")
	flag.StringVar(&cfg.SNI, "sni", "", "SNI for Reality (empty = use cert/key)")
	flag.StringVar(&cfg.Password, "password", "", "Auth password (required)")
	flag.StringVar(&cfg.Pool, "pool", "10.10.0.0/24", "VPN IP pool")
	flag.StringVar(&cfg.DNS, "dns", "8.8.8.8", "DNS to push")
	flag.IntVar(&cfg.MTU, "mtu", 1399, "Tunnel MTU")
	flag.StringVar(&cfg.CertFile, "cert", "", "TLS cert file")
	flag.StringVar(&cfg.KeyFile, "key", "", "TLS key file")
	flag.Parse()

	if cfg.Password == "" {
		log.Fatal("-password required")
	}

	var err error
	ipPool, err = NewIPPool(cfg.Pool)
	if err != nil {
		log.Fatal("IP pool:", err)
	}

	// TLS config
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			log.Fatal("cert:", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	} else if cfg.SNI != "" {
		// Reality mode: steal cert from SNI target
		// TODO: integrate NekoPass-Core Reality
		log.Printf("Reality mode: SNI=%s (needs NekoPass-Core integration)", cfg.SNI)
		// For now, generate self-signed
		log.Fatal("Reality mode not yet implemented. Use -cert/-key instead.")
	} else {
		log.Fatal("Need -cert/-key or -sni")
	}

	ln, err := tls.Listen("tcp", cfg.Listen, tlsCfg)
	if err != nil {
		log.Fatal("listen:", err)
	}

	hn, _ := os.Hostname()
	log.Printf("NekoConnect VPN server on %s (pool=%s, mtu=%d, host=%s)", cfg.Listen, cfg.Pool, cfg.MTU, hn)

	mux := http.NewServeMux()
	mux.HandleFunc("/", handlePortal)
	mux.HandleFunc("/+CSCOE+/logon.html", handlePortal)
	mux.HandleFunc("/auth", handleAuth)

	// Use custom server to handle both HTTP and CONNECT
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "CONNECT" {
				handleTunnel(w, r)
				return
			}
			mux.ServeHTTP(w, r)
		}),
	}
	log.Fatal(server.Serve(ln))
}

// handlePortal serves the Cisco ASA login page
func handlePortal(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "Cisco ASA SSL VPN")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `<html><head><title>SSL VPN Service</title></head>
<body><h2>SSL VPN Service</h2><p>Please use Cisco AnyConnect client to connect.</p></body></html>`)
}

// handleAuth processes AnyConnect XML authentication
func handleAuth(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	bodyStr := string(body)

	// Check password in XML body
	if !strings.Contains(bodyStr, cfg.Password) {
		w.WriteHeader(401)
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request">
<auth id="main"><message>Authentication failed</message>
<form><input type="password" name="password" label="Password:"/></form></auth></config-auth>`)
		return
	}

	// Generate token
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	sessionsMu.Lock()
	sessions[token] = &Session{Token: token, Created: time.Now()}
	sessionsMu.Unlock()

	w.Header().Set("Content-Type", "text/xml")
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete">
<auth id="success"><message>Welcome</message></auth>
<session-token>%s</session-token></config-auth>`, token)
}

// handleTunnel handles CONNECT /CSCOSSLC/tunnel — the actual VPN tunnel
func handleTunnel(w http.ResponseWriter, r *http.Request) {
	// Validate session
	cookie, _ := r.Cookie("webvpn")
	if cookie == nil {
		w.WriteHeader(401)
		return
	}

	sessionsMu.RLock()
	sess, ok := sessions[cookie.Value]
	sessionsMu.RUnlock()
	if !ok {
		w.WriteHeader(401)
		return
	}

	// Allocate IP
	clientIP, err := ipPool.Allocate()
	if err != nil {
		w.WriteHeader(503)
		return
	}
	sess.IP = clientIP
	defer ipPool.Release(clientIP)

	// Client info
	masterSecret := r.Header.Get("X-DTLS-Master-Secret")
	_ = masterSecret // TODO: DTLS channel

	hn, _ := os.Hostname()

	// Send tunnel response headers (AnyConnect protocol)
	w.Header().Set("Server", "NekoConnect")
	w.Header().Set("X-CSTP-Version", "1")
	w.Header().Set("X-CSTP-Server-Name", "NekoConnect")
	w.Header().Set("X-CSTP-Protocol", "Copyright (c) 2004 Cisco Systems, Inc.")
	w.Header().Set("X-CSTP-Address", clientIP.String())
	w.Header().Set("X-CSTP-Netmask", net.IP(ipPool.Mask()).String())
	w.Header().Set("X-CSTP-Hostname", hn)
	w.Header().Set("X-CSTP-DNS", cfg.DNS)
	w.Header().Set("X-CSTP-MTU", fmt.Sprintf("%d", cfg.MTU))
	w.Header().Set("X-CSTP-DPD", "30")
	w.Header().Set("X-CSTP-Keepalive", "20")
	w.Header().Set("X-CSTP-Lease-Duration", "1209600")
	w.Header().Set("X-CSTP-Session-Timeout", "none")
	w.Header().Set("X-CSTP-Idle-Timeout", "18000")
	w.Header().Set("X-CSTP-Disconnected-Timeout", "18000")
	w.Header().Set("X-CSTP-Keep", "true")
	w.Header().Set("X-CSTP-Tunnel-All-DNS", "false")
	w.Header().Set("X-CSTP-Rekey-Time", "86400")
	w.Header().Set("X-CSTP-Rekey-Method", "new-tunnel")
	w.Header().Set("X-DTLS-Rekey-Time", "86400")
	w.Header().Set("X-CSTP-Split-Exclude", "0.0.0.0/255.255.255.255")
	w.WriteHeader(200)

	// Hijack connection for raw CSTP framing
	hj, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	conn, bufRW, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	log.Printf("TUNNEL: %s → %s (user=%s)", conn.RemoteAddr(), clientIP, sess.Username)

	// CSTP read/write loop
	go cstpWriter(conn, clientIP)
	cstpReader(conn, bufRW, clientIP)
}

func cstpReader(conn net.Conn, bufRW *bufio.ReadWriter, clientIP net.IP) {
	defer conn.Close()
	buf := make([]byte, 65536)

	for {
		conn.SetReadDeadline(time.Now().Add(40 * time.Second))
		n, err := bufRW.Read(buf)
		if err != nil {
			log.Printf("CSTP read error: %s %v", clientIP, err)
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
				// TODO: write to TUN device
				log.Printf("DATA: %d bytes from %s", dataLen, clientIP)
			}
		case PktDPD_REQ:
			// Send DPD response
			resp := make([]byte, 8)
			copy(resp, plHeader)
			resp[6] = PktDPD_RESP
			conn.Write(resp)
		case PktKEEPALIVE:
			// Echo keepalive
			resp := make([]byte, 8)
			copy(resp, plHeader)
			resp[6] = PktKEEPALIVE
			conn.Write(resp)
		case PktDISCONNECT:
			log.Printf("DISCONNECT: %s", clientIP)
			return
		}
	}
}

func cstpWriter(conn net.Conn, clientIP net.IP) {
	// TODO: read from TUN device and send to client
	// For now, just send periodic DPD requests
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		resp := make([]byte, 8)
		copy(resp, plHeader)
		resp[6] = PktDPD_REQ
		if _, err := conn.Write(resp); err != nil {
			return
		}
	}
}

// IPPool manages VPN client IPs
type IPPool struct {
	mu      sync.Mutex
	network *net.IPNet
	used    map[string]bool
	gateway net.IP
}

func NewIPPool(cidr string) (*IPPool, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	gw := make(net.IP, len(ip))
	copy(gw, ip)
	gw[len(gw)-1]++
	return &IPPool{network: network, used: map[string]bool{gw.String(): true}, gateway: gw}, nil
}

func (p *IPPool) Allocate() (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ip := make(net.IP, len(p.network.IP))
	copy(ip, p.network.IP)
	for ip[len(ip)-1] = 2; ip[len(ip)-1] < 254; ip[len(ip)-1]++ {
		if p.network.Contains(ip) && !p.used[ip.String()] {
			a := make(net.IP, len(ip))
			copy(a, ip)
			p.used[a.String()] = true
			return a, nil
		}
	}
	return nil, fmt.Errorf("pool exhausted")
}

func (p *IPPool) Release(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.used, ip.String())
}

func (p *IPPool) Mask() net.IPMask { return p.network.Mask }
