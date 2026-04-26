package main

// CN IP bypass — exclude Chinese IP ranges from VPN tunnel
// Downloads and caches chnroutes for Split-Exclude

import (
	"bufio"
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

const chnroutesURL = "https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt"

var (
	cnRoutes    []string // CN CIDR (for exclude mode)
	nonCNRoutes []string // non-CN CIDR (for include mode)
	cnRoutesMu  sync.RWMutex
)

func loadCNRoutes(cacheFile string) error {
	// Try cache first
	if cacheFile != "" {
		if info, err := os.Stat(cacheFile); err == nil {
			// Use cache if less than 24h old
			if time.Since(info.ModTime()) < 24*time.Hour {
				return loadCNRoutesFromFile(cacheFile)
			}
		}
	}

	// Download fresh
	log.Printf("Downloading CN routes from %s ...", chnroutesURL)
	resp, err := http.Get(chnroutesURL)
	if err != nil {
		// Fallback to cache even if stale
		if cacheFile != "" {
			if err2 := loadCNRoutesFromFile(cacheFile); err2 == nil {
				log.Printf("Using stale CN routes cache")
				return nil
			}
		}
		return fmt.Errorf("download CN routes: %w", err)
	}
	defer resp.Body.Close()

	routes, err := parseCNRoutes(resp.Body)
	if err != nil {
		return err
	}

	cnRoutesMu.Lock()
	cnRoutes = routes
	cnRoutesMu.Unlock()

	log.Printf("Loaded %d CN routes", len(routes))
	invertCNRoutes()

	// Save to cache
	if cacheFile != "" {
		saveCNRoutesCache(cacheFile, routes)
	}

	return nil
}

func loadCNRoutesFromFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	routes, err := parseCNRoutes(f)
	if err != nil {
		return err
	}

	cnRoutesMu.Lock()
	cnRoutes = routes
	cnRoutesMu.Unlock()

	log.Printf("Loaded %d CN routes from cache %s", len(routes), path)
	invertCNRoutes()
	return nil
}

func parseCNRoutes(r io.Reader) ([]string, error) {
	var routes []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Validate CIDR
		_, _, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		routes = append(routes, line)
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("no valid CN routes found")
	}
	return routes, nil
}

func saveCNRoutesCache(path string, routes []string) {
	f, err := os.Create(path)
	if err != nil {
		return
	}
	defer f.Close()
	for _, r := range routes {
		fmt.Fprintln(f, r)
	}
}

// getCNHeaders returns Split-Exclude or Split-Include headers based on mode
func getCNHeaders(mode string) string {
	cnRoutesMu.RLock()
	defer cnRoutesMu.RUnlock()

	var sb strings.Builder
	switch mode {
	case "exclude":
		for _, cidr := range cnRoutes {
			sb.WriteString(fmt.Sprintf("X-CSTP-Split-Exclude: %s\r\n", cidrToMask(cidr)))
		}
	case "include":
		for _, cidr := range nonCNRoutes {
			sb.WriteString(fmt.Sprintf("X-CSTP-Split-Include: %s\r\n", cidrToMask(cidr)))
		}
	}
	return sb.String()
}

// Periodic refresh (every 12h)
func startCNRoutesRefresh(cacheFile string) {
	go func() {
		for {
			time.Sleep(12 * time.Hour)
			if err := loadCNRoutes(cacheFile); err != nil {
				log.Printf("CN routes refresh: %v", err)
			}
		}
	}()
}

// invertCNRoutes computes non-CN IP ranges from CN ranges
func invertCNRoutes() {
	cnRoutesMu.RLock()
	routes := make([]string, len(cnRoutes))
	copy(routes, cnRoutes)
	cnRoutesMu.RUnlock()

	// Parse CN networks
	type ipRange struct{ start, end uint32 }
	var ranges []ipRange
	for _, cidr := range routes {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil { continue }
		ip4 := ipnet.IP.To4()
		if ip4 == nil { continue }
		start := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
		mask := uint32(ipnet.Mask[0])<<24 | uint32(ipnet.Mask[1])<<16 | uint32(ipnet.Mask[2])<<8 | uint32(ipnet.Mask[3])
		end := start | ^mask
		ranges = append(ranges, ipRange{start, end})
	}

	// Sort by start
	for i := 0; i < len(ranges); i++ {
		for j := i + 1; j < len(ranges); j++ {
			if ranges[j].start < ranges[i].start {
				ranges[i], ranges[j] = ranges[j], ranges[i]
			}
		}
	}

	// Generate non-CN ranges (gaps between CN ranges)
	var nonCN []string
	var cursor uint32 = 0
	for _, r := range ranges {
		if r.start > cursor {
			nonCN = append(nonCN, rangeToList(cursor, r.start-1)...)
		}
		if r.end >= cursor {
			cursor = r.end + 1
		}
	}
	// Remaining after last CN range (up to 223.255.255.255, skip multicast)
	if cursor <= 0xDFFFFFFF {
		nonCN = append(nonCN, rangeToList(cursor, 0xDFFFFFFF)...)
	}

	cnRoutesMu.Lock()
	nonCNRoutes = nonCN
	cnRoutesMu.Unlock()
	log.Printf("Generated %d non-CN routes (include mode)", len(nonCN))
}

// rangeToList converts an IP range to minimal CIDR list
func rangeToList(start, end uint32) []string {
	var result []string
	for start <= end {
		// Find largest block starting at 'start' that fits in [start, end]
		maxBits := 32
		for bits := 1; bits <= 32; bits++ {
			mask := uint32(0xFFFFFFFF) << uint32(bits)
			if (start & mask) != start { break }
			blockEnd := start | ^mask
			if blockEnd <= end {
				maxBits = bits
			}
		}
		prefix := 32 - maxBits
		result = append(result, fmt.Sprintf("%d.%d.%d.%d/%d",
			byte(start>>24), byte(start>>16), byte(start>>8), byte(start), prefix))
		blockSize := uint32(1) << uint32(maxBits)
		if start+blockSize < start { break } // overflow
		start += blockSize
	}
	return result
}
