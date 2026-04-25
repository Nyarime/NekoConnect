package tunnel

import (
	"fmt"
	"net"
	"sync"
)

// IPPool manages VPN client IP allocation
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
	gateway := make(net.IP, len(ip))
	copy(gateway, ip)
	gateway[len(gateway)-1]++ // .1 is gateway

	return &IPPool{
		network: network,
		used:    map[string]bool{gateway.String(): true},
		gateway: gateway,
	}, nil
}

func (p *IPPool) Allocate() (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	ip := make(net.IP, len(p.network.IP))
	copy(ip, p.network.IP)

	for ip[len(ip)-1] = 2; ip[len(ip)-1] < 254; ip[len(ip)-1]++ {
		if p.network.Contains(ip) && !p.used[ip.String()] {
			allocated := make(net.IP, len(ip))
			copy(allocated, ip)
			p.used[allocated.String()] = true
			return allocated, nil
		}
	}
	return nil, fmt.Errorf("IP pool exhausted")
}

func (p *IPPool) Release(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.used, ip.String())
}

func (p *IPPool) Gateway() net.IP { return p.gateway }
func (p *IPPool) Mask() net.IPMask { return p.network.Mask }
