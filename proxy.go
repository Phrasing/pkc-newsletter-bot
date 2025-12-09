package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"strings"
	"sync"
)

type ProxyManager struct {
	proxies []string // http://user:pass@host:port format (normalized)
	raw     []string // original format from file
	display []string // ip:port for logging (no credentials)
	index   int
	mu      sync.Mutex
}

// parseProxyLine parses a proxy string in various formats and returns normalized URL and display string.
// Supported formats:
//   - ip:port:username:password
//   - ip:port (IP authenticated, no credentials)
//   - http://username:password@ip:port
//   - https://username:password@ip:port
//   - http://ip:port (IP authenticated)
//   - https://ip:port (IP authenticated)
func parseProxyLine(line string) (proxyURL, display string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", false
	}

	// Check if it's already a URL format
	if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
		parsed, err := url.Parse(line)
		if err != nil {
			return "", "", false
		}

		// Extract host:port for display
		display = parsed.Host

		// Normalize to http:// (most proxy clients expect http)
		// Keep credentials if present
		if parsed.User != nil {
			password, _ := parsed.User.Password()
			proxyURL = fmt.Sprintf("http://%s:%s@%s", parsed.User.Username(), password, parsed.Host)
		} else {
			// IP authenticated proxy
			proxyURL = fmt.Sprintf("http://%s", parsed.Host)
		}
		return proxyURL, display, true
	}

	// Parse colon-separated format
	parts := strings.Split(line, ":")

	switch len(parts) {
	case 2:
		// ip:port (IP authenticated)
		host, port := parts[0], parts[1]
		proxyURL = fmt.Sprintf("http://%s:%s", host, port)
		display = fmt.Sprintf("%s:%s", host, port)
		return proxyURL, display, true

	case 4:
		// ip:port:username:password
		host, port, user, pass := parts[0], parts[1], parts[2], parts[3]
		proxyURL = fmt.Sprintf("http://%s:%s@%s:%s", user, pass, host, port)
		display = fmt.Sprintf("%s:%s", host, port)
		return proxyURL, display, true

	default:
		return "", "", false
	}
}

// NewProxyManager loads proxies from file.
// Supported formats per line:
//   - ip:port:username:password
//   - ip:port (IP authenticated)
//   - http://username:password@ip:port
//   - https://username:password@ip:port
//   - http://ip:port
//   - https://ip:port
func NewProxyManager(filename string) (*ProxyManager, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open proxy file: %w", err)
	}
	defer file.Close()

	var proxies []string
	var raw []string
	var display []string

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		proxyURL, disp, ok := parseProxyLine(line)
		if !ok {
			// Log warning but continue
			continue
		}

		proxies = append(proxies, proxyURL)
		raw = append(raw, line)
		display = append(display, disp)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading proxy file: %w", err)
	}

	if len(proxies) == 0 {
		return nil, fmt.Errorf("no valid proxies found in %s", filename)
	}

	return &ProxyManager{
		proxies: proxies,
		raw:     raw,
		display: display,
		index:   0,
	}, nil
}

func (pm *ProxyManager) Current() string {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.proxies[pm.index]
}

func (pm *ProxyManager) CurrentRaw() string {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.raw[pm.index]
}

func (pm *ProxyManager) CurrentDisplay() string {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.display[pm.index]
}

func (pm *ProxyManager) Rotate() string {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.index = (pm.index + 1) % len(pm.proxies)
	return pm.proxies[pm.index]
}

func (pm *ProxyManager) Count() int {
	return len(pm.proxies)
}

func (pm *ProxyManager) Index() int {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.index
}

// Random returns a random proxy URL and its index for display lookup.
func (pm *ProxyManager) Random() (proxyURL string, idx int) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	idx = rand.Intn(len(pm.proxies))
	return pm.proxies[idx], idx
}

// DisplayAt returns the display string for proxy at given index.
func (pm *ProxyManager) DisplayAt(idx int) string {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if idx >= 0 && idx < len(pm.display) {
		return pm.display[idx]
	}
	return ""
}
