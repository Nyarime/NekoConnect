package main

// Reality TLS — disguise traffic as a connection to a real SSL VPN
// Inspired by XTLS Reality + NekoPass-Core implementation
//
// Two modes:
// 1. Mirror cert (visible CN matches real server, but self-signed)
//    → Stealthy but client shows cert warning unless TOFU
// 2. Cert pin via X-CSTP-Server-Cert-Hash (AnyConnect TOFU model)
//    → After first manual accept, subsequent connections silent
//
// For maximum stealth WITHOUT cert warnings, use -autocert with own domain.

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"time"
)

// FetchRemoteCert connects to a real SSL VPN server and grabs its certificate
// This cert is used for fingerprint matching (DPI sees same cert details)
func FetchRemoteCert(sni string) (*x509.Certificate, error) {
	addr := sni
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = sni + ":443"
	}
	host, _, _ := net.SplitHostPort(addr)

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", addr, err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certs")
	}
	cert := state.PeerCertificates[0]
	log.Printf("Reality: stole cert from %s — CN=%s, SAN=%v",
		sni, cert.Subject.CommonName, cert.DNSNames)
	return cert, nil
}

// MirrorCertConfig generates a self-signed cert mimicking the remote server's
// Subject/SAN, useful for matching JA3 fingerprints. Note: clients will see
// cert verification fail (different signer).
func MirrorCertConfig(remoteCert *x509.Certificate) (*tls.Config, error) {
	// In a real implementation, generate self-signed with same Subject + SAN
	// For now, return a placeholder that documents the intent
	return &tls.Config{
		// Real implementation would use generated mirror cert
		MinVersion: tls.VersionTLS12,
	}, fmt.Errorf("mirror cert generation not yet implemented — use -autocert for production")
}

// CertHashSHA256 returns the SHA-256 fingerprint of a cert as base64
// (matches AnyConnect's pin-sha256 format)
func CertHashSHA256(cert *x509.Certificate) string {
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	_ = pemBlock
	// TODO: compute pin-sha256 hash
	return ""
}
