# NekoConnect

AnyConnect-compatible SSL VPN server with Reality TLS stealth.

## Features

- **AnyConnect Compatible** — Works with Cisco AnyConnect, OpenConnect, and any CSTP-based client
- **Reality Stealth** — SNI-based traffic routing; unauthorized traffic transparently proxied to real Cisco ASA
- **Zero Config TLS** — Let's Encrypt auto-cert, self-signed, or custom certificates
- **Pure Go** — Single binary, zero dependencies, cross-platform
- **TUN + NAT** — Automatic network configuration with iptables MASQUERADE
- **VPN Profile Push** — AnyConnect XML profile auto-delivered to clients

## Quick Start

```bash
# Download
wget https://github.com/Nyarime/NekoConnect/releases/latest/download/nekoconnect-linux-amd64
chmod +x nekoconnect-linux-amd64

# Run (self-signed cert, split tunnel)
./nekoconnect -listen :443 -password YOUR_SECRET -pool 10.10.0.0/24

# Run with Let's Encrypt (recommended for production)
./nekoconnect -listen :443 -password YOUR_SECRET -pool 10.10.0.0/24 \
  -autocert vpn.yourdomain.com

# Run with Reality stealth (ultimate mode)
./nekoconnect -listen :443 -password YOUR_SECRET -pool 10.10.0.0/24 \
  -cert server.crt -key server.key \
  -our-sni vpn.yourdomain.com \
  -upstream-tcp vpn.real-university.edu:443
```

## Client Setup

### Cisco AnyConnect / OpenConnect

1. Open AnyConnect → Enter server address
2. Accept certificate warning (first time only — automatically pinned after)
3. Enter password
4. Connected ✅

```bash
# OpenConnect CLI
echo "YOUR_SECRET" | openconnect --user=vpn --passwd-on-stdin \
  --servercert=pin-sha256:XXXX https://your-server:443
```

### Split Tunnel

By default, only VPN subnet traffic is routed through the tunnel. Your existing internet connection is not affected.

## Architecture

```
                    ┌─────────────────────┐
 AnyConnect ──TLS──▶│   NekoConnect :443   │
 Client             │                     │
                    │  SNI Router          │
                    │  ├─ our-sni → VPN   │──▶ TUN ──▶ Internet
                    │  └─ other  → proxy  │──▶ Real Cisco ASA
                    └─────────────────────┘
```

## Deployment Modes

| Mode | TLS | Stealth | Cert Warning |
|------|-----|---------|-------------|
| `--autocert` | Let's Encrypt | Medium | None ✅ |
| `--cert/--key` | Self-signed | Low | First connect only |
| `--our-sni + --upstream-tcp` | Self-signed + SNI route | **Maximum** | First connect only |

## Protocol Support

| Feature | Status |
|---------|--------|
| CSTP (TLS tunnel) | ✅ Full |
| DTLS (UDP accel) | 🔧 Framework |
| AnyConnect XML Auth | ✅ Full |
| VPN Profile Push | ✅ Full |
| DPD / Keepalive | ✅ Full |
| Split Tunnel | ✅ Full |
| TUN + NAT | ✅ Full |
| IP Pool | ✅ Full |
| SNI Routing | ✅ Full |
| Let's Encrypt | ✅ Full |

## Tested Clients

- ✅ OpenConnect (Linux/macOS)
- 🔧 Cisco AnyConnect (Windows/macOS/iOS/Android) — protocol compatible, pending real-device test
- ✅ Remote tunnel verified: ping 8.8.8.8 via VPN, 0% loss

## Building

```bash
git clone https://github.com/Nyarime/NekoConnect
cd NekoConnect
go build -o nekoconnect ./cmd/server/
```

## Credits

- Protocol reference: [anylink](https://github.com/bjdgyc/anylink) (AGPL-3.0)
- Protocol reference: [ocserv](https://gitlab.com/openconnect/ocserv)
- TLS stealth: Inspired by [XTLS Reality](https://github.com/XTLS/Xray-core)
- Built with [NekoPass-Core](https://github.com/Nyarime/NekoPass-Core) technology

## License

**NekoConnect is dual-licensed:**

- **AGPL-3.0** for open-source and non-commercial use
- **Commercial License** available from [Naixi Networks](https://naixi.net) for proprietary deployments

See [LICENSE](LICENSE) for details.

---

© 2026 [Naixi Networks](https://naixi.net). All rights reserved.
