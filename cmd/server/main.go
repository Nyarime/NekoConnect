package main

// NekoConnect — AnyConnect-compatible VPN server
// Based on anylink (github.com/bjdgyc/anylink) protocol implementation
// + NekoPass-Core Reality TLS stealth

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os/exec"

	"github.com/songgao/water"
	"golang.org/x/crypto/acme/autocert"
	"os"
	"strconv"
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
	Upstream    string
	UsersFile   string
	AdminAddr   string
	AdminToken  string
	OAuthFile   string
	DBFile      string
	OurSNI      string
	UpstreamTCP string
}

// Session
type Session struct {
	Group    *GroupConfig
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
	writePid()
	defer removePid()
	
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
	// Start DTLS server on same port
	// Parse listen port for DTLS
	dtlsPort = 443
	if parts := strings.Split(cfg.Listen, ":"); len(parts) > 0 {
		if p, e := strconv.Atoi(parts[len(parts)-1]); e == nil && p > 0 { dtlsPort = p }
	}
	if err := startDTLSServer(dtlsPort); err != nil {
		log.Printf("DTLS start: %v (UDP acceleration disabled)", err)
	}
}

func main() {
	if handleSubcommand() { return }
	flag.StringVar(&cfg.Listen, "listen", ":443", "Listen address")
	flag.StringVar(&cfg.SNI, "sni", "", "SNI for Reality (empty = use cert/key)")
	flag.StringVar(&cfg.Password, "password", "", "Auth password (single-password mode)")
	flag.StringVar(&cfg.UsersFile, "users", "", "Users config file (JSON, multi-user mode)")
	flag.StringVar(&cfg.AdminAddr, "admin", "", "Admin API listen address (e.g. 127.0.0.1:9091)")
	flag.StringVar(&cfg.AdminToken, "admin-token", "", "Admin API bearer token")
	flag.StringVar(&cfg.OAuthFile, "oauth", "", "OAuth/OIDC config file (JSON)")
	flag.StringVar(&cfg.DBFile, "db", "", "SQLite database file (enables DB mode)")
	flag.StringVar(&cfg.Pool, "pool", "10.10.0.0/24", "VPN IP pool")
	flag.StringVar(&cfg.DNS, "dns", "8.8.8.8", "DNS to push")
	flag.IntVar(&cfg.MTU, "mtu", 1399, "Tunnel MTU")
	flag.StringVar(&cfg.CertFile, "cert", "", "TLS cert file")
	flag.StringVar(&cfg.KeyFile, "key", "", "TLS key file")
	flag.StringVar(&cfg.AutoCert, "autocert", "", "Domain for Let's Encrypt auto cert (e.g. vpn.mydomain.com)")
	flag.StringVar(&cfg.CertCache, "cert-cache", "/var/cache/nekoconnect-certs", "Autocert cache dir")
	flag.StringVar(&cfg.Upstream, "upstream", "", "HTTP reverse proxy target for unauthorized requests")
	flag.StringVar(&cfg.OurSNI, "our-sni", "", "Our SNI domain (TLS-routed to VPN; other SNIs → upstream-tcp)")
	flag.StringVar(&cfg.UpstreamTCP, "upstream-tcp", "", "Raw TCP forward target for unmatched SNI (e.g. vpn2fa.hku.hk:443)")
	flag.Parse()

	if cfg.Password == "" && cfg.UsersFile == "" {
		log.Fatal("-password or -users required")
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

	// SNI router mode: split traffic by SNI
	if cfg.OurSNI != "" && cfg.UpstreamTCP != "" {
		rawLn, err := net.Listen("tcp", cfg.Listen)
		if err != nil { log.Fatal("listen:", err) }
		log.Printf("SNI router: %q → VPN, others → %s", cfg.OurSNI, cfg.UpstreamTCP)

		mux := http.NewServeMux()
		mux.HandleFunc("/", handlePortal)
		mux.HandleFunc("/+CSCOE+/logon.html", handlePortal)
		mux.HandleFunc("/auth", handleAuth)
		mux.HandleFunc("/profiles/vpn.xml", handleProfile)
		mux.HandleFunc("/CACerts/", handleProfile)
		mux.HandleFunc("/sso/callback", handleOAuthCallback)
		mux.HandleFunc("/sso/wait", handleSSOWait)

		router := &SNIRouter{
			OurSNIs:     []string{cfg.OurSNI},
			UpstreamTCP: cfg.UpstreamTCP,
			TLSConfig:   tlsCfg,
			HTTPHandler: func(c *tls.Conn) {
				server := &http.Server{
					Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.Method == "CONNECT" { handleTunnel(w, r); return }
						mux.ServeHTTP(w, r)
					}),
				}
				oneShotLn := &oneShotListener{conn: c}
				server.Serve(oneShotLn)
			},
		}

		writePid()
	defer removePid()
	setupNAT()
	
		log.Printf("NekoConnect VPN server on %s (pool=%s, mtu=%d)", cfg.Listen, cfg.Pool, cfg.MTU)
		for {
			conn, err := rawLn.Accept()
			if err != nil { continue }
			go router.HandleConn(conn)
		}
		return
	}

	ln, err := tls.Listen("tcp", cfg.Listen, tlsCfg)
	if err != nil {
		log.Fatal("listen:", err)
	}

	hn, _ := os.Hostname()
	initUpstream()
	writePid()
	defer removePid()
	setupNAT()
	startAdminAPI(cfg.AdminAddr, cfg.AdminToken)
	log.Printf("NekoConnect VPN server on %s (pool=%s, mtu=%d, host=%s)", cfg.Listen, cfg.Pool, cfg.MTU, hn)

	mux := http.NewServeMux()
	mux.HandleFunc("/", handlePortal)
	mux.HandleFunc("/+CSCOE+/logon.html", handlePortal)
	mux.HandleFunc("/auth", handleAuth)
	mux.HandleFunc("/profiles/vpn.xml", handleProfile)
	mux.HandleFunc("/CACerts/", handleProfile)
	mux.HandleFunc("/sso/callback", handleOAuthCallback)
	mux.HandleFunc("/sso/wait", handleSSOWait)

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


// vpnProfileXML is the AnyConnect Profile that gets pushed to clients
const vpnProfileXML = `<?xml version="1.0" encoding="UTF-8"?>
<AnyConnectProfile xmlns="http://schemas.xmlsoap.org/encoding/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://schemas.xmlsoap.org/encoding/ AnyConnectProfile.xsd">
<ClientInitialization>
<UseStartBeforeLogon UserControllable="true">false</UseStartBeforeLogon>
<AutomaticCertSelection UserControllable="true">true</AutomaticCertSelection>
<ShowPreConnectMessage>false</ShowPreConnectMessage>
<CertificateStore>All</CertificateStore>
<CertificateStoreOverride>false</CertificateStoreOverride>
<ProxySettings>Native</ProxySettings>
<AllowLocalProxyConnections>false</AllowLocalProxyConnections>
<AuthenticationTimeout>30</AuthenticationTimeout>
<AutoConnectOnStart UserControllable="true">false</AutoConnectOnStart>
<MinimizeOnConnect UserControllable="true">true</MinimizeOnConnect>
<LocalLanAccess UserControllable="true">false</LocalLanAccess>
<DisableCaptivePortalDetection UserControllable="true">false</DisableCaptivePortalDetection>
<ClearSmartcardPin UserControllable="true">true</ClearSmartcardPin>
<IPProtocolSupport>IPv4,IPv6</IPProtocolSupport>
<AutoReconnect UserControllable="false">true
<AutoReconnectBehavior UserControllable="false">DisconnectOnSuspend</AutoReconnectBehavior>
</AutoReconnect>
<AutoUpdate UserControllable="false">false</AutoUpdate>
<RSASecurIDIntegration UserControllable="false">Automatic</RSASecurIDIntegration>
<WindowsLogonEnforcement>SingleLocalLogon</WindowsLogonEnforcement>
<WindowsVPNEstablishment>LocalUsersOnly</WindowsVPNEstablishment>
<AutomaticVPNPolicy>false</AutomaticVPNPolicy>
<PPPExclusion UserControllable="false">Disable
<PPPExclusionServerIP UserControllable="false"></PPPExclusionServerIP>
</PPPExclusion>
<EnableScripting UserControllable="false">false</EnableScripting>
<EnableAutomaticServerSelection UserControllable="false">false
<AutoServerSelectionImprovement>20</AutoServerSelectionImprovement>
<AutoServerSelectionSuspendTime>4</AutoServerSelectionSuspendTime>
</EnableAutomaticServerSelection>
<RetainVpnOnLogoff>false</RetainVpnOnLogoff>
</ClientInitialization>
<ServerList>
<HostEntry>
<HostName>NekoConnect VPN</HostName>
<HostAddress>vpn2fa.hku.hk</HostAddress>
</HostEntry>
</ServerList>
</AnyConnectProfile>`

// vpnProfileSHA1 returns sha1 hex of the profile
func vpnProfileSHA1() string {
	h := sha1.Sum([]byte(vpnProfileXML))
	return fmt.Sprintf("%x", h)
}

// handleProfile serves the VPN profile XML to AnyConnect clients
func handleProfile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/xml")
	w.Write([]byte(vpnProfileXML))
}

var (
	appVersion   = "dev"
	appCommit    = "unknown"
	appBuildDate = "unknown"
)

var upstreamProxy *httputil.ReverseProxy
var dtlsPort = 443
type ConfigAuthResponse struct {
	XMLName xml.Name `xml:"config-auth"`
	Auth    *AuthPayload `xml:"auth"`
}
type AuthPayload struct {
	Username string `xml:"username"`
	Password string `xml:"password"`
}

var tokenUserMap sync.Map // session-token → username

func initUpstream() {
	if cfg.DBFile != "" {
		if err := initDB(cfg.DBFile); err != nil {
			log.Fatal("database:", err)
		}
	}
	if cfg.OAuthFile != "" {
		data, err := os.ReadFile(cfg.OAuthFile)
		if err != nil { log.Fatal("oauth config:", err) }
		var oc OAuthConfig
		if err := json.Unmarshal(data, &oc); err != nil { log.Fatal("oauth parse:", err) }
		initOAuth(&oc)
	}
	if cfg.UsersFile != "" {
		if err := loadUsers(cfg.UsersFile); err != nil {
			log.Fatal("load users:", err)
		}
	}
	if cfg.Upstream == "" { return }
	u, err := url.Parse(cfg.Upstream)
	if err != nil { log.Fatal("upstream parse:", err) }
	upstreamProxy = httputil.NewSingleHostReverseProxy(u)
	upstreamProxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	origDirector := upstreamProxy.Director
	upstreamProxy.Director = func(req *http.Request) {
		origDirector(req)
		req.Host = u.Host
	}
	log.Printf("Reverse proxy: unauthorized → %s", cfg.Upstream)
}

func proxyToUpstream(w http.ResponseWriter, r *http.Request) {
	if upstreamProxy == nil {
		w.Header().Set("Server", "Cisco ASA SSL VPN")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><h2>Cisco Secure Client</h2><p>The Webportal Login is disabled.</p></body></html>`)
		return
	}
	upstreamProxy.ServeHTTP(w, r)
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
	clientAddr := r.RemoteAddr

	w.Header().Set("Content-Type", "text/xml")

	// Parse XML to extract username/password
	var cr ConfigAuthResponse
	xml.Unmarshal(body, &cr)

	username := ""
	password := ""
	if cr.Auth != nil {
		username = cr.Auth.Username
		password = cr.Auth.Password
	}

	// If OAuth enabled and client supports SSO, offer it
	if password == "" && oauthCfg != nil {
		ssoResponse := handleOAuthStart(w, r)
		if ssoResponse != "" {
			w.Header().Set("Content-Type", "text/xml")
			fmt.Fprint(w, ssoResponse)
			return
		}
	}

	// No password yet → send auth form
	if password == "" {
		groups := getGroupNames()
		var groupOpts string
		for _, g := range groups {
			groupOpts += fmt.Sprintf("<option value=\"%s\">%s</option>\n", g, g)
		}
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
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

	// Check login lock
	if loginLock.IsLocked(username) || loginLock.IsLocked(clientAddr) {
		AuditLog(username, "auth_locked", clientAddr, "")
		http.Error(w, "Account locked", http.StatusTooManyRequests)
		return
	}

	// Authenticate
	authResult := authenticateUser(username, password)
	if !authResult.OK {
		loginLock.RecordFail(username)
		loginLock.RecordFail(clientAddr)
		AuditLog(username, "auth_fail", clientAddr, "")
		// Replay to upstream
		r.Body = io.NopCloser(strings.NewReader(bodyStr))
		r.ContentLength = int64(len(bodyStr))
		proxyToUpstream(w, r)
		return
	}

	loginLock.RecordSuccess(username)
	loginLock.RecordSuccess(clientAddr)
	AuditLog(username, "login", clientAddr, "")

	// Generate token
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	sessionsMu.Lock()
	sessions[token] = &Session{Token: token, Created: time.Now(), Group: authResult.Group}
	sessionsMu.Unlock()
	tokenUserMap.Store(token, authResult.Username)

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
<config client="vpn" type="private">
<vpn-profile-manifest>
<vpn rev="1.0">
<file type="profile" service-type="user">
<uri>/profiles/vpn.xml</uri>
<hash type="sha1">%s</hash>
</file>
</vpn>
</vpn-profile-manifest>
</config>
</config-auth>`, token, vpnProfileSHA1())
}


// cidrToMask converts "10.0.0.0/8" to "10.0.0.0/255.0.0.0" for AnyConnect
func cidrToMask(cidr string) string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return cidr
	}
	return fmt.Sprintf("%s/%s", ipnet.IP.String(), net.IP(ipnet.Mask).String())
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
	username := ""
	if val, ok := tokenUserMap.Load(cookie.Value); ok {
		username = val.(string)
	}
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
	// DNS from group config or default
	groupDNS := cfg.DNS
	groupRoutes := []string{cfg.Pool}
	if val, ok := tokenUserMap.Load(cookie.Value); ok {
		un := val.(string)
		ar := authenticateUser(un, "") // won't match password, but we need group
		_ = ar // lookup below
	}
	// Lookup group from session
	if sess.Group != nil {
		if sess.Group.DNS != "" { groupDNS = sess.Group.DNS }
		if len(sess.Group.Routes) > 0 { groupRoutes = sess.Group.Routes }
	}
	resp.WriteString(fmt.Sprintf("X-CSTP-DNS: %s\r\n", groupDNS))
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
	for _, route := range groupRoutes {
		resp.WriteString(fmt.Sprintf("X-CSTP-Split-Include: %s\r\n", cidrToMask(route)))
	}
	dtlsSid := ""
	if masterSecret != "" {
		dtlsSid = RandomHex(32)
		// Register DTLS session BEFORE sending response (client starts DTLS immediately)
		RegisterDTLSSession(dtlsSid, masterSecret, nil, nil)
		resp.WriteString(DTLSResponseHeaders(dtlsPort, dtlsSid))
		resp.WriteString(fmt.Sprintf("X-DTLS-MTU: %d\r\n", cfg.MTU))
	}
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

	log.Printf("TUN %s up: gw=%s client=%s mtu=%d user=%s", tunName, gw, clientIP, cfg.MTU, username)
	RegisterOnline(clientIP.String(), username, "", r.RemoteAddr, r.RemoteAddr)
	defer func() {
		UnregisterOnline(clientIP.String())
		AuditLog(username, "logout", r.RemoteAddr, "vpn="+clientIP.String())
	}()
	if masterSecret != "" && dtlsSid != "" {
		// Update session with TUN (was pre-registered without it)
		RegisterDTLSSession(dtlsSid, masterSecret, clientIP, tun)
		defer UnregisterDTLSSession(dtlsSid)
	}

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


// oneShotListener wraps a single conn as a net.Listener for http.Server
type oneShotListener struct {
	conn net.Conn
	done bool
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.done { return nil, fmt.Errorf("done") }
	l.done = true
	return l.conn, nil
}
func (l *oneShotListener) Close() error { return nil }
func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }

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
