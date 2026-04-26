package main

// Smart CN bypass for AnyConnect 200-route limit
// Strategy: pure non-CN /8 blocks + important services in mixed /8 blocks
// Total: ~140 routes, well under 200 limit, all platforms compatible

import (
	"bufio"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const apnicURL = "http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"

var (
	smartRoutes   []string // final <200 routes for Split-Include
	smartRoutesMu sync.RWMutex
)

// Important non-CN services in mixed /8 blocks
// These /8 blocks contain both CN and non-CN IPs
var importantNonCN = []string{
	// Cloudflare (1.x mixed with CN)
	"1.0.0.0/24",
	"1.1.1.0/24",
	// Google (142.x, 172.x mixed)
	"142.250.0.0/15",
	"172.217.0.0/16",
	"172.253.0.0/16",
	"172.64.0.0/13", // Cloudflare ranges
	// GitHub (140.x mixed)
	"140.82.112.0/20",
	// Reddit/Fastly (151.x mixed)
	"151.101.0.0/16",
	// GitHub CDN (199.x mixed)
	"199.232.0.0/16",
	// Facebook/Meta (157.x mixed)
	"157.240.0.0/16",
	// Telegram (149.x mixed)
	"149.154.0.0/16",
	// Twitter (69.x mixed)
	"69.195.160.0/19",
	// Wikipedia (198.x mixed)
	"198.35.26.0/23",
	// Discord (162.x mixed)
	"162.159.0.0/16",
	// OpenAI
	"199.59.148.0/22",
	// Netflix (198.x mixed)
	"198.38.96.0/19",
}

func buildSmartRoutes(cnCacheFile string) error {
	// Step 1: Get CN /8 blocks from APNIC
	cn8 := make(map[int]bool)

	// Try APNIC first
	resp, err := http.Get(apnicURL)
	if err == nil {
		defer resp.Body.Close()
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.Contains(line, "|CN|ipv4|") {
				continue
			}
			parts := strings.Split(line, "|")
			if len(parts) < 5 {
				continue
			}
			ip := parts[3]
			first, _ := strconv.Atoi(strings.Split(ip, ".")[0])
			if first > 0 {
				cn8[first] = true
			}
		}
	}

	// Fallback: load from cache file
	if len(cn8) == 0 && cnCacheFile != "" {
		f, err := os.Open(cnCacheFile)
		if err == nil {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				parts := strings.SplitN(line, ".", 2)
				if len(parts) > 0 {
					first, _ := strconv.Atoi(parts[0])
					if first > 0 {
						cn8[first] = true
					}
				}
			}
		}
	}

	if len(cn8) == 0 {
		return fmt.Errorf("no CN data available")
	}

	// Step 2: Build routes
	var routes []string

	// Part 1: Pure non-CN /8 blocks
	for i := 1; i < 224; i++ {
		if !cn8[i] {
			routes = append(routes, fmt.Sprintf("%d.0.0.0/8", i))
		}
	}
	part1 := len(routes)

	// Part 2: Important non-CN services in mixed /8 blocks
	routes = append(routes, importantNonCN...)

	log.Printf("Smart routes: %d pure /8 + %d important = %d total (limit 200)",
		part1, len(importantNonCN), len(routes))

	if len(routes) > 200 {
		log.Printf("WARNING: %d routes exceeds AnyConnect 200 limit, truncating", len(routes))
		routes = routes[:200]
	}

	smartRoutesMu.Lock()
	smartRoutes = routes
	smartRoutesMu.Unlock()

	return nil
}

// getSmartIncludeHeaders returns Split-Include headers for the smart route list
func getSmartIncludeHeaders() string {
	smartRoutesMu.RLock()
	defer smartRoutesMu.RUnlock()

	var sb strings.Builder
	for _, cidr := range smartRoutes {
		sb.WriteString(fmt.Sprintf("X-CSTP-Split-Include: %s\r\n", cidrToMask(cidr)))
	}
	return sb.String()
}

// loadAPNICRoutes downloads and parses APNIC CN routes (full CIDR list)
func loadAPNICRoutes() ([]string, error) {
	resp, err := http.Get(apnicURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var routes []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "|CN|ipv4|") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 5 {
			continue
		}
		ip := parts[3]
		count, _ := strconv.Atoi(parts[4])
		if count <= 0 {
			continue
		}
		prefix := 32 - int(math.Log2(float64(count)))
		routes = append(routes, fmt.Sprintf("%s/%d", ip, prefix))
	}
	return routes, nil
}

// Periodic refresh
func startSmartRoutesRefresh(cnCache string) {
	go func() {
		for {
			time.Sleep(12 * time.Hour)
			if err := buildSmartRoutes(cnCache); err != nil {
				log.Printf("Smart routes refresh: %v", err)
			}
		}
	}()
}

// Unused import guard
var _ = net.ParseCIDR
