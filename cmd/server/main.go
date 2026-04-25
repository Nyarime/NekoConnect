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
	"os/exec"

	"github.com/songgao/water"
	"golang.org/x/crypto/acme/autocert"
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
	CertFile  string
	KeyFile   string
	AutoCert  string
	CertCache string
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

// setupNAT enables IP forwarding + NAT MASQUERADE for VPN clients
func setupNAT() {
	exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	// Find primary interface
	out, _ := exec.Command("sh", "-c", "ip route | grep default | awk '{print $5}' | head -1").Output()
	iface := strings.TrimSpace(string(out))
	if iface == "" { iface = "eth0" }
	// Add MASQUERADE rule (idempotent)
	exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", cfg.Pool, "-o", iface, "-j", "MASQUERADE").Run()
	exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", cfg.Pool, "-o", iface, "-j", "MASQUERADE").Run()
	exec.Command("iptables", "-D", "FORWARD", "-s", cfg.Pool, "-j", "ACCEPT").Run()
	exec.Command("iptables", "-A", "FORWARD", "-s", cfg.Pool, "-j", "ACCEPT").Run()
	exec.Command("iptables", "-D", "FORWARD", "-d", cfg.Pool, "-j", "ACCEPT").Run()
	exec.Command("iptables", "-A", "FORWARD", "-d", cfg.Pool, "-j", "ACCEPT").Run()
	log.Printf("NAT enabled: %s → %s (MASQUERADE)", cfg.Pool, iface)
}

func main() {
	flag.StringVar(&cfg.Listen, "listen", ":443", "Listen address")
	flag.StringVar(&cfg.SNI, "sni", "", "SNI for Reality (empty = use cert/key)")
	flag.StringVar(&cfg.Password, "password", "", "Auth password (required)")
	flag.StringVar(&cfg.Pool, "pool", "10.10.0.0/24", "VPN IP pool")
	flag.StringVar(&cfg.DNS, "dns", "8.8.8.8", "DNS to push")
	flag.IntVar(&cfg.MTU, "mtu", 1399, "Tunnel MTU")
	flag.StringVar(&cfg.CertFile, "cert", "", "TLS cert file")
	flag.StringVar(&cfg.KeyFile, "key", "", "TLS key file")
	flag.StringVar(&cfg.AutoCert, "autocert", "", "Domain for Let's Encrypt auto cert (e.g. vpn.mydomain.com)")
	flag.StringVar(&cfg.CertCache, "cert-cache", "/var/cache/nekoconnect-certs", "Autocert cache dir")
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
	if cfg.AutoCert != "" {
		// Let's Encrypt automatic cert
		m := &autocert.Manager{
			Cache:      autocert.DirCache(cfg.CertCache),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.AutoCert),
		}
		tlsCfg.GetCertificate = m.GetCertificate
		// Start HTTP-01 challenge listener on :80
		go http.ListenAndServe(":80", m.HTTPHandler(nil))
		log.Printf("AutoCert enabled for %s (HTTP-01 on :80)", cfg.AutoCert)
	} else if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			log.Fatal("cert:", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	} else if cfg.SNI != "" {
		// Reality mode: fetch remote cert for fingerprint matching
		remoteCert, err := FetchRemoteCert(cfg.SNI)
		if err != nil {
			log.Fatal("Reality fetch:", err)
		}
		_, err = MirrorCertConfig(remoteCert)
		if err != nil {
			log.Printf("Reality limitation: %v", err)
			log.Fatal("Use -autocert <domain> for production deployments")
		}
	} else {
		log.Fatal("Need -autocert <domain>, -cert/-key, or -sni")
	}

	ln, err := tls.Listen("tcp", cfg.Listen, tlsCfg)
	if err != nil {
		log.Fatal("listen:", err)
	}

	hn, _ := os.Hostname()
	setupNAT()
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
	// removed: w.Header().Set("Server", "Cisco ASA SSL VPN")
	// POST = AnyConnect auth request (XML)
	if r.Method == "POST" {
		handleAuth(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `<html><head><title>SSL VPN Service</title></head>
<body><h2>SSL VPN Service</h2><p>Please use Cisco AnyConnect client to connect.</p></body></html>`)
}

// handleAuth processes AnyConnect XML authentication
func handleAuth(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	bodyStr := string(body)

	w.Header().Set("Content-Type", "text/xml")

	// First request: no password → send auth form
	if !strings.Contains(bodyStr, cfg.Password) {
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<opaque is-for="sg">
<tunnel-group>VPN</tunnel-group>
<group-alias>VPN</group-alias>
<aggauth-handle>168179266</aggauth-handle>
<config-hash>1595829378234</config-hash>
</opaque>
<auth id="main">
<title>Login</title>
<message>Please enter your credentials</message>
<banner></banner>
<form>
<input type="text" name="username" label="Username:"></input>
<input type="password" name="password" label="Password:"></input>
</form>
</auth>
</config-auth>`)
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
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
<session-token>%s</session-token>
<auth id="success">
<banner>Welcome to NekoConnect VPN</banner>
<message id="0" param1="" param2=""></message>
</auth>
<capabilities>
<crypto-supported>ssl-dhe</crypto-supported>
</capabilities>
</config-auth>`, token)
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

	// Send tunnel response headers (AnyConnect protocol)
	// removed: w.Header().Set("Server", "NekoConnect")
	// removed: w.Header().Set("X-CSTP-Version", "1")
	// removed: w.Header().Set("X-CSTP-Server-Name", "NekoConnect")
	// removed: w.Header().Set("X-CSTP-Protocol", "Copyright (c) 2004 Cisco Systems, Inc.")
	// removed: w.Header().Set("X-CSTP-Address", clientIP.String())
	// removed: w.Header().Set("X-CSTP-Netmask", net.IP(ipPool.Mask()).String())
	// removed: w.Header().Set("X-CSTP-DNS", cfg.DNS)
	// removed: w.Header().Set("X-CSTP-MTU", fmt.Sprintf("%d", cfg.MTU))
	// removed: w.Header().Set("X-CSTP-DPD", "30")
	// removed: w.Header().Set("X-CSTP-Keepalive", "20")
	// removed: w.Header().Set("X-CSTP-Lease-Duration", "1209600")
	// removed: w.Header().Set("X-CSTP-Session-Timeout", "none")
	// removed: w.Header().Set("X-CSTP-Idle-Timeout", "18000")
	// removed: w.Header().Set("X-CSTP-Disconnected-Timeout", "18000")
	// removed: w.Header().Set("X-CSTP-Keep", "true")
	// removed: w.Header().Set("X-CSTP-Tunnel-All-DNS", "false")
	// removed: w.Header().Set("X-CSTP-Rekey-Time", "86400")
	// Hijack FIRST, then write raw response (WriteHeader doesn't work well for CONNECT)
	hj, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	conn, bufRW, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	// Write raw HTTP 200 + CSTP headers
	var resp strings.Builder
	resp.WriteString("HTTP/1.1 200 CONNECTED\r\n")
	resp.WriteString("Server: NekoConnect\r\n")
	resp.WriteString("X-CSTP-Version: 1\r\n")
	resp.WriteString("X-CSTP-Server-Name: vpn2fa.hku.hk\r\n")
	resp.WriteString(fmt.Sprintf("X-CSTP-Address: %s\r\n", clientIP.String()))
	resp.WriteString(fmt.Sprintf("X-CSTP-Netmask: %s\r\n", net.IP(ipPool.Mask()).String()))
	resp.WriteString(fmt.Sprintf("X-CSTP-DNS: %s\r\n", cfg.DNS))
	resp.WriteString(fmt.Sprintf("X-CSTP-MTU: %d\r\n", cfg.MTU))
	resp.WriteString("X-CSTP-DPD: 30\r\n")
	resp.WriteString("X-CSTP-Keepalive: 20\r\n")
	resp.WriteString("X-CSTP-Lease-Duration: 1209600\r\n")
	resp.WriteString("X-CSTP-Session-Timeout: none\r\n")
	resp.WriteString("X-CSTP-Idle-Timeout: 18000\r\n")
	resp.WriteString("X-CSTP-Disconnected-Timeout: 18000\r\n")
	resp.WriteString("X-CSTP-Keep: true\r\n")
	resp.WriteString("X-CSTP-Tunnel-All-DNS: false\r\n")
	resp.WriteString("X-CSTP-Rekey-Time: 86400\r\n")
	resp.WriteString("X-CSTP-Rekey-Method: new-tunnel\r\n")
	resp.WriteString("X-DTLS-Rekey-Time: 86400\r\n")
	resp.WriteString("X-CSTP-Split-Include: 10.99.0.0/255.255.255.0\r\n")
	resp.WriteString("\r\n")
	conn.Write([]byte(resp.String()))

	log.Printf("TUNNEL: %s → %s (user=%s)", conn.RemoteAddr(), clientIP, sess.Username)

	// Create TUN device for this session
	tun, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		log.Printf("TUN create failed: %v", err)
		return
	}
	defer tun.Close()
	tunName := tun.Name()

	// Configure TUN: assign gateway IP, bring up, set MTU
	gw := ipPool.Gateway()
	exec.Command("ip", "link", "set", "dev", tunName, "up", "mtu", fmt.Sprintf("%d", cfg.MTU)).Run()
	exec.Command("ip", "addr", "add", fmt.Sprintf("%s/24", gw.String()), "dev", tunName).Run()
	exec.Command("ip", "route", "add", clientIP.String()+"/32", "dev", tunName).Run()
	defer exec.Command("ip", "route", "del", clientIP.String()+"/32", "dev", tunName).Run()

	log.Printf("TUN %s up: gw=%s client=%s mtu=%d", tunName, gw, clientIP, cfg.MTU)

	// CSTP <-> TUN bridge
	go tunToCstp(tun, conn, clientIP)
	cstpToTun(conn, bufRW, tun, clientIP)
}

// cstpToTun: read CSTP DATA frames from client, write to TUN
func cstpToTun(conn net.Conn, bufRW *bufio.ReadWriter, tun *water.Interface, clientIP net.IP) {
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
				// Write IP packet to TUN
				tun.Write(buf[8 : 8+int(dataLen)])
			}
		case PktDPD_REQ:
			resp := make([]byte, 8)
			copy(resp, plHeader)
			resp[6] = PktDPD_RESP
			conn.Write(resp)
		case PktKEEPALIVE:
			// no response needed
		case PktDISCONNECT:
			log.Printf("DISCONNECT: %s", clientIP)
			return
		}
	}
}

// tunToCstp: read packets from TUN, send as CSTP DATA frames to client
func tunToCstp(tun *water.Interface, conn net.Conn, clientIP net.IP) {
	buf := make([]byte, 65536)
	frame := make([]byte, 65536)

	for {
		n, err := tun.Read(buf)
		if err != nil {
			log.Printf("TUN read error: %v", err)
			return
		}
		if n == 0 {
			continue
		}

		// Build CSTP DATA frame
		copy(frame, plHeader)
		binary.BigEndian.PutUint16(frame[4:6], uint16(n))
		frame[6] = PktDATA
		copy(frame[8:], buf[:n])

		if _, err := conn.Write(frame[:8+n]); err != nil {
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
func (p *IPPool) Gateway() net.IP { return p.gateway }
