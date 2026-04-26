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
	cnRoutes   []string // CIDR format
	cnRoutesMu sync.RWMutex
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

// getCNExcludeHeaders returns X-CSTP-Split-Exclude headers for all CN IPs
func getCNExcludeHeaders() string {
	cnRoutesMu.RLock()
	defer cnRoutesMu.RUnlock()

	var sb strings.Builder
	for _, cidr := range cnRoutes {
		sb.WriteString(fmt.Sprintf("X-CSTP-Split-Exclude: %s\r\n", cidrToMask(cidr)))
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
