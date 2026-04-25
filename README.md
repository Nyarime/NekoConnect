# NekoConnect

AnyConnect-compatible VPN server with Reality TLS stealth.

## Features

- **原版 AnyConnect 客户端兼容** — Cisco AnyConnect / OpenConnect 直连
- **Reality TLS** — 偷取真实 VPN 服务器证书，流量不可区分
- **CSTP + DTLS** — 双通道加速
- **纯 Go** — 零 CGO，全平台

## Architecture

```
AnyConnect Client ──TLS──→ NekoConnect Server
                              ├── Reality (证书偷取)
                              ├── Portal (Cisco ASA 认证)
                              ├── CSTP (TLS 隧道)
                              └── DTLS (UDP 加速)
                              ↓
                           TUN → 内核路由
```

## Usage

```bash
nekoconnect -listen :443 -sni vpn.company.com -password SECRET -pool 10.10.0.0/24
```

## Credits

Built on [NekoPass-Core](https://github.com/Nyarime/NekoPass-Core) technology.

## License

Proprietary — Naixi Networks
