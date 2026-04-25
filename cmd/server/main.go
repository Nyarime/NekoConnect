package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/Nyarime/NekoConnect/pkg/auth"
	"github.com/Nyarime/NekoConnect/pkg/cstp"
	"github.com/Nyarime/NekoConnect/pkg/tunnel"
)

func main() {
	listen := flag.String("listen", ":443", "Listen address")
	sni := flag.String("sni", "vpn.example.com", "SNI for Reality cert stealing")
	password := flag.String("password", "", "Authentication password")
	pool := flag.String("pool", "10.10.0.0/24", "VPN IP pool CIDR")
	dns := flag.String("dns", "8.8.8.8", "DNS server to push")
	mtu := flag.Int("mtu", 1400, "MTU")
	flag.Parse()

	if *password == "" {
		log.Fatal("--password required")
	}

	// Initialize IP pool
	ipPool, err := tunnel.NewIPPool(*pool)
	if err != nil {
		log.Fatal("IP pool:", err)
	}

	// Auth manager
	authMgr := auth.NewManager(*password)

	// TLS config with Reality cert stealing
	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return stealCert(*sni, hello)
		},
		NextProtos: []string{"http/1.1"},
	}

	// Listen
	ln, err := tls.Listen("tcp", *listen, tlsConfig)
	if err != nil {
		log.Fatal("Listen:", err)
	}
	log.Printf("NekoConnect listening on %s (SNI: %s, Pool: %s)", *listen, *sni, *pool)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleConn(conn, authMgr, ipPool, *dns, *mtu)
	}
}

func handleConn(conn net.Conn, authMgr *auth.Manager, ipPool *tunnel.IPPool, dns string, mtu int) {
	defer conn.Close()

	// Read HTTP request
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	switch {
	case req.URL.Path == "/":
		// Portal page
		resp := "HTTP/1.1 200 OK\r\nServer: Cisco ASA SSL VPN\r\nContent-Type: text/html\r\n\r\n"
		resp += `<html><head><meta http-equiv="refresh" content="0;url=/+CSCOE+/logon.html"></head></html>`
		conn.Write([]byte(resp))

	case strings.Contains(req.URL.Path, "/+CSCOE+/logon.html"):
		// Login page
		resp := "HTTP/1.1 200 OK\r\nServer: Cisco ASA SSL VPN\r\nContent-Type: text/html\r\n\r\n"
		resp += "<html><body><h1>SSL VPN Portal</h1><p>Use AnyConnect client to connect.</p></body></html>"
		conn.Write([]byte(resp))

	case req.Method == "POST" && strings.Contains(req.URL.Path, "auth"):
		// XML Authentication
		cookie, err := authMgr.Authenticate(req)
		if err != nil {
			conn.Write([]byte("HTTP/1.1 401 Unauthorized\r\n\r\n"))
			return
		}
		xmlResp := auth.AnyConnectXMLResponse(cookie, "")
		resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: %d\r\n\r\n%s", len(xmlResp), xmlResp)
		conn.Write([]byte(resp))

	case req.Method == "CONNECT" && strings.Contains(req.URL.Path, "CSCOSSLC/tunnel"):
		// CSTP Tunnel — this is the VPN data channel!
		cookie := req.Header.Get("Cookie")
		if !authMgr.ValidateSession(extractWebVPNCookie(cookie)) {
			conn.Write([]byte("HTTP/1.1 401 Unauthorized\r\n\r\n"))
			return
		}

		// Allocate IP
		clientIP, err := ipPool.Allocate()
		if err != nil {
			conn.Write([]byte("HTTP/1.1 503 Service Unavailable\r\n\r\n"))
			return
		}
		defer ipPool.Release(clientIP)

		// Send tunnel headers
		mask := net.IP(ipPool.Mask()).String()
		headers := cstp.CSTPHeaders(clientIP.String(), mask, dns, mtu, nil)
		resp := "HTTP/1.1 200 CONNECTED\r\n" + headers + "\r\n"
		conn.Write([]byte(resp))

		log.Printf("CSTP tunnel established: %s → %s", conn.RemoteAddr(), clientIP)

		// Enter CSTP framing mode
		cstpConn := cstp.NewServerConn(conn)
		handleTunnel(cstpConn, clientIP)

	default:
		conn.Write([]byte("HTTP/1.1 404 Not Found\r\nServer: Cisco ASA SSL VPN\r\n\r\n"))
	}
}

func handleTunnel(conn *cstp.Conn, clientIP net.IP) {
	// TODO: Create TUN device and bridge packets
	// For now, just handle DPD/keepalive
	for {
		frame, err := conn.ReadFrame()
		if err != nil {
			return
		}

		switch frame.Type {
		case cstp.TypeDATA:
			// TODO: Write to TUN device
			log.Printf("DATA: %d bytes from %s", len(frame.Payload), clientIP)

		case cstp.TypeDPD_REQ:
			conn.WriteDPDResponse()

		case cstp.TypeKEEPALIVE:
			conn.WriteKeepalive()

		case cstp.TypeDISCONNECT:
			log.Printf("Client %s disconnected", clientIP)
			return
		}
	}
}

func extractWebVPNCookie(cookieHeader string) string {
	for _, part := range strings.Split(cookieHeader, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "webvpn=") {
			return strings.TrimPrefix(part, "webvpn=")
		}
	}
	return ""
}

// stealCert connects to the real VPN server and mirrors its certificate
func stealCert(sni string, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// Connect to real server
	dialer := &tls.Dialer{
		Config: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         sni,
		},
	}
	conn, err := dialer.DialContext(hello.Context(), "tcp", sni+":443")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certs")
	}

	// Use the remote cert (this won't have the private key, need self-signed with same CN)
	// In production, use NekoPass-Core's Reality implementation
	return nil, fmt.Errorf("Reality cert stealing requires NekoPass-Core integration — use -cert/-key for now")
}
