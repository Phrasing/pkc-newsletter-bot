package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/Hyper-Solutions/hyper-sdk-go/v2"
	"github.com/Hyper-Solutions/hyper-sdk-go/v2/incapsula"
	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
)

// Reese84TokenResponse represents the response from the Reese84 challenge endpoint.
type Reese84TokenResponse struct {
	Token        string `json:"token"`
	RenewInSec   int    `json:"renewInSec"`
	CookieDomain string `json:"cookieDomain"`
}

// SolveStaticReese84 proactively solves the static Reese84 challenge that's present on all page loads.
// This should be called during session initialization before making other requests.
func SolveStaticReese84(ctx context.Context, client tls_client.HttpClient, session *hyper.Session, baseURL, proxyURL, scriptPath string, profile *BrowserProfile) (*Reese84TokenResponse, error) {
	scriptURL := baseURL + scriptPath

	// Parse the base URL to extract the domain for the sensor submission
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	domain := parsedURL.Host

	// Sensor submission URL uses the same path with ?d=domain query parameter
	sensorURL := baseURL + scriptPath + "?d=" + domain

	// Step 1: Fetch the static challenge script
	scriptContent, err := fetchScript(client, scriptURL, profile)
	if err != nil {
		return nil, err
	}

	externalIP, err := getExternalIP(proxyURL, session.ApiKey)
	if err != nil {
		return nil, err
	}

	// Rate limit Hyper API calls
	limiter := GetHyperLimiter(3)
	limiter.Acquire()
	defer limiter.Release()

	// Step 2: Generate the sensor payload using Hyper API
	// For static sensors, use the home page URL (with trailing slash) as pageUrl
	sensor, err := session.GenerateReese84Sensor(ctx, &hyper.ReeseInput{
		UserAgent:      profile.UserAgent,
		AcceptLanguage: "en-US,en;q=0.9",
		IP:             externalIP,
		ScriptUrl:      scriptURL,
		PageUrl:        baseURL + "/",
		Script:         scriptContent,
	})

	if err != nil {
		if ContainsFatalErrorString(err) {
			return nil, NewFatalError(err)
		}
		return nil, err
	}

	// Step 3: Submit the sensor payload
	tokenResp, err := submitSensor(client, sensorURL, sensor, profile)
	if err != nil {
		return nil, err
	}

	// Step 4: Set the reese84 cookie
	cookieDomain := tokenResp.CookieDomain
	if cookieDomain == "" {
		// Use domain with leading dot to make it accessible across all subdomains
		cookieDomain = "." + strings.TrimPrefix(domain, "www.")
	}

	cookie := &http.Cookie{
		Name:   "reese84",
		Value:  tokenResp.Token,
		Domain: cookieDomain,
		Path:   "/",
	}

	cookieURL, _ := url.Parse(baseURL)
	client.SetCookies(cookieURL, []*http.Cookie{cookie})

	return tokenResp, nil
}

// SolveReese84 handles the full Reese84 challenge flow.
// It detects the challenge, generates the sensor payload, submits it, and sets the reese84 cookie.
func SolveReese84(ctx context.Context, client tls_client.HttpClient, session *hyper.Session, pageURL, proxyURL string, challengeBody io.Reader, profile *BrowserProfile) (*Reese84TokenResponse, error) {
	// Step 1: Parse the script path from the challenge page
	sensorPath, scriptPath, err := incapsula.ParseDynamicReeseScript(challengeBody, pageURL)
	if err != nil {
		return nil, err
	}

	fmt.Println(scriptPath)

	// Build full URLs
	parsedURL, err := url.Parse(pageURL)
	if err != nil {
		return nil, err
	}
	baseURL := parsedURL.Scheme + "://" + parsedURL.Host
	scriptURL := baseURL + scriptPath
	sensorURL := baseURL + sensorPath

	// Step 2: Fetch the challenge script
	scriptContent, err := fetchScript(client, scriptURL, profile)
	if err != nil {
		return nil, err
	}

	externalIP, err := getExternalIP(proxyURL, session.ApiKey)
	if err != nil {
		return nil, err
	}

	// Rate limit Hyper API calls
	limiter := GetHyperLimiter(3)
	limiter.Acquire()
	defer limiter.Release()

	// Step 4: Generate the sensor payload using Hyper API
	sensor, err := session.GenerateReese84Sensor(ctx, &hyper.ReeseInput{
		UserAgent:      profile.UserAgent,
		AcceptLanguage: "en-US,en;q=0.9",
		IP:             externalIP,
		ScriptUrl:      scriptURL,
		PageUrl:        pageURL,
		Script:         scriptContent,
	})

	if err != nil {
		if ContainsFatalErrorString(err) {
			return nil, NewFatalError(err)
		}
		return nil, err
	}

	// Step 4: Submit the sensor payload
	tokenResp, err := submitSensor(client, sensorURL, sensor, profile)
	if err != nil {
		return nil, err
	}

	// Step 5: Set the reese84 cookie
	cookieDomain := tokenResp.CookieDomain
	if cookieDomain == "" {
		// Use domain with leading dot to make it accessible across all subdomains
		host := parsedURL.Host
		cookieDomain = "." + strings.TrimPrefix(host, "www.")
	}

	fmt.Printf("[DEBUG] Dynamic Reese84 - Token: %s, Domain: %s, RenewInSec: %d\n",
		tokenResp.Token, cookieDomain, tokenResp.RenewInSec)

	cookie := &http.Cookie{
		Name:   "reese84",
		Value:  tokenResp.Token,
		Domain: cookieDomain,
		Path:   "/",
	}

	cookieURL, _ := url.Parse(baseURL)
	client.SetCookies(cookieURL, []*http.Cookie{cookie})

	return tokenResp, nil
}

// fetchScript fetches the Reese84 challenge script.
func fetchScript(client tls_client.HttpClient, scriptURL string, profile *BrowserProfile) (string, error) {
	req, err := http.NewRequest(http.MethodGet, scriptURL, nil)
	if err != nil {
		return "", err
	}

	req.Header = http.Header{
		"user-agent":         {profile.UserAgent},
		"accept":             {"*/*"},
		"accept-language":    {"en-US,en;q=0.9"},
		"sec-fetch-dest":     {"script"},
		"sec-fetch-mode":     {"no-cors"},
		"sec-fetch-site":     {"same-origin"},
		"sec-ch-ua":          {profile.SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"sec-ch-ua-platform": {`"Windows"`},
		http.HeaderOrderKey: {
			"user-agent",
			"accept",
			"accept-language",
			"sec-fetch-dest",
			"sec-fetch-mode",
			"sec-fetch-site",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
		},
		http.PHeaderOrderKey: PseudoHeaderOrder,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// submitSensor posts the sensor payload to the challenge endpoint.
func submitSensor(client tls_client.HttpClient, submitURL, sensor string, profile *BrowserProfile) (*Reese84TokenResponse, error) {
	req, err := http.NewRequest(http.MethodPost, submitURL, strings.NewReader(sensor))
	if err != nil {
		return nil, err
	}

	req.Header = http.Header{
		"user-agent":         {profile.UserAgent},
		"accept":             {"*/*"},
		"accept-language":    {"en-US,en;q=0.9"},
		"content-type":       {"text/plain;charset=UTF-8"},
		"origin":             {getOrigin(submitURL)},
		"sec-fetch-dest":     {"empty"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-site":     {"same-origin"},
		"sec-ch-ua":          {profile.SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"sec-ch-ua-platform": {`"Windows"`},
		http.HeaderOrderKey: {
			"user-agent",
			"accept",
			"accept-language",
			"content-type",
			"origin",
			"sec-fetch-dest",
			"sec-fetch-mode",
			"sec-fetch-site",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
		},
		http.PHeaderOrderKey: PseudoHeaderOrder,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var tokenResp Reese84TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// getOrigin extracts the origin (scheme + host) from a URL.
func getOrigin(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

// IsReese84Challenge checks if the response body contains a Reese84 challenge.
func IsReese84Challenge(body string) bool {
	return strings.Contains(body, "Pardon Our Interruption")
}

// hyperIPResponse represents the response from Hyper's IP endpoint.
type hyperIPResponse struct {
	IP string `json:"ip"`
}

// getExternalIP fetches the external IP address using Hyper's IP endpoint.
// proxyURL should be in format: http://user:pass@host:port
func getExternalIP(proxyURL, apiKey string) (string, error) {
	client := &fasthttp.Client{
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		Dial:         fasthttpproxy.FasthttpHTTPDialer(proxyURL),
	}

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("https://ip.hypersolutions.co/ip")
	req.Header.SetMethod(fasthttp.MethodGet)
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("accept", "application/json")

	if err := client.Do(req, resp); err != nil {
		return "", err
	}

	var ipResp hyperIPResponse
	if err := json.Unmarshal(resp.Body(), &ipResp); err != nil {
		return "", err
	}

	return ipResp.IP, nil
}
