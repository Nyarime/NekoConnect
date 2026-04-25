package main

// SNI Router — sniff TLS ClientHello to route connections
// based on SNI before TLS termination

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

// peekedConn lets us re-use the bytes we already read for SNI sniffing
type peekedConn struct {
	net.Conn
	buf io.Reader
}

func (p *peekedConn) Read(b []byte) (int, error) { return p.buf.Read(b) }

// extractSNI parses a TLS ClientHello to extract the SNI extension.
// Returns ("", err) on failure. The full bytes are returned for replay.
func extractSNI(conn net.Conn, timeout time.Duration) (string, []byte, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{})

	br := bufio.NewReader(conn)
	// TLS record header: ContentType(1) + Version(2) + Length(2)
	hdr, err := br.Peek(5)
	if err != nil {
		return "", nil, err
	}
	if hdr[0] != 0x16 { // not Handshake
		return "", nil, fmt.Errorf("not TLS handshake")
	}
	recordLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recordLen < 4 || recordLen > 16384 {
		return "", nil, fmt.Errorf("bad record length")
	}
	full, err := br.Peek(5 + recordLen)
	if err != nil {
		return "", nil, err
	}

	sni := parseSNIFromClientHello(full[5:])

	// Build a conn that replays the peeked bytes
	return sni, full, nil
}

// parseSNIFromClientHello extracts SNI from raw handshake bytes
func parseSNIFromClientHello(data []byte) string {
	// Handshake header: HandshakeType(1) + Length(3)
	if len(data) < 4 || data[0] != 0x01 {
		return ""
	}
	hsLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if 4+hsLen > len(data) {
		return ""
	}
	body := data[4 : 4+hsLen]

	// Skip: Version(2) + Random(32) + SessionIDLen(1) + SessionID
	if len(body) < 34 {
		return ""
	}
	pos := 34
	if pos >= len(body) {
		return ""
	}
	sidLen := int(body[pos])
	pos += 1 + sidLen
	if pos+2 > len(body) {
		return ""
	}
	// CipherSuitesLen(2) + CipherSuites
	csLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2 + csLen
	if pos+1 > len(body) {
		return ""
	}
	// CompressionMethodsLen(1) + CompressionMethods
	cmLen := int(body[pos])
	pos += 1 + cmLen
	if pos+2 > len(body) {
		return ""
	}
	// ExtensionsLen(2) + Extensions
	extLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	end := pos + extLen
	if end > len(body) {
		return ""
	}

	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(body[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		pos += 4
		if pos+extDataLen > end {
			return ""
		}
		if extType == 0x00 { // SNI
			ext := body[pos : pos+extDataLen]
			if len(ext) < 5 {
				return ""
			}
			// SNI list length(2) + entries
			pos2 := 2
			if ext[pos2] != 0x00 { // host_name type
				return ""
			}
			pos2 += 1
			nameLen := int(binary.BigEndian.Uint16(ext[pos2 : pos2+2]))
			pos2 += 2
			if pos2+nameLen > len(ext) {
				return ""
			}
			return string(ext[pos2 : pos2+nameLen])
		}
		pos += extDataLen
	}
	return ""
}

// SNIRouter handles incoming TCP, sniffs SNI, and routes accordingly
type SNIRouter struct {
	OurSNIs     []string  // SNIs that route to our VPN handler
	UpstreamTCP string    // TCP forward target for unmatched SNIs (e.g. "vpn2fa.hku.hk:443")
	TLSConfig   *tls.Config
	HTTPHandler func(*tls.Conn)  // called for our SNI matches
}

func (r *SNIRouter) HandleConn(rawConn net.Conn) {
	defer rawConn.Close()

	sni, peeked, err := extractSNI(rawConn, 5*time.Second)
	if err != nil {
		log.Printf("SNI extract: %v from %s", err, rawConn.RemoteAddr())
		return
	}

	// Replay peeked bytes
	pc := &peekedConn{Conn: rawConn, buf: io.MultiReader(bytes.NewReader(peeked), rawConn)}

	// Check if this is one of our SNIs
	for _, ours := range r.OurSNIs {
		if strings.EqualFold(sni, ours) {
			// Our VPN — terminate TLS, hand to handler
			tlsConn := tls.Server(pc, r.TLSConfig)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			r.HTTPHandler(tlsConn)
			return
		}
	}

	// Unknown SNI → transparent TCP forward to upstream
	if r.UpstreamTCP == "" {
		// No upstream configured, just close
		return
	}

	upConn, err := net.DialTimeout("tcp", r.UpstreamTCP, 5*time.Second)
	if err != nil {
		log.Printf("Upstream dial fail: %v", err)
		return
	}
	defer upConn.Close()

	log.Printf("SNI route: %q → upstream %s", sni, r.UpstreamTCP)

	// Bidirectional forward
	done := make(chan struct{}, 2)
	go func() { io.Copy(upConn, pc); done <- struct{}{} }()
	go func() { io.Copy(rawConn, upConn); done <- struct{}{} }()
	<-done
}
