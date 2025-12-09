package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/Hyper-Solutions/hyper-sdk-go/v2"
	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/google/uuid"
)

const (
	// PKC URLs
	pkcBaseURL        = "https://www.pokemoncenter.com"
	pkcHomeURL        = pkcBaseURL + "/"
	pkcCartDataURL    = pkcBaseURL + "/tpci-ecommweb-api/cart/data?type=mini"
	pkcProfileDataURL = pkcBaseURL + "/tpci-ecommweb-api/profile/data?checkRole=true"
	pkcEmailSignupURL = pkcBaseURL + "/tpci-ecommweb-api/email/signup"

	// reCAPTCHA sitekey for email signup
	pkcRecaptchaSiteKey = "6Lc4P0MoAAAAAAhyCYBhoVfHZUF3HMvFdXSRZ-kO"

	// maxChallengeRetries limits recursive challenge solving to prevent infinite loops
	maxChallengeRetries = 3

	// maxSignupProxyRetries limits proxy rotation retries for connection errors during signup
	maxSignupProxyRetries = 5

	// maxCaptchaRetries limits captcha token retries for identity-based policy denials
	maxCaptchaRetries = 5
)

// PKCClient wraps the HTTP client with Pokemon Center specific functionality.
type PKCClient struct {
	client       tls_client.HttpClient
	session      *hyper.Session
	logger       Logger
	externalIP   string         // Cached external IP for the proxy
	headers      *hyper.Headers // Headers returned from Hyper API (sec-ch-ua-full-version-list, etc.)
	proxy        string         // Proxy in CapSolver format (http://user:pass@ip:port)
	proxyManager *ProxyManager  // Optional proxy manager for rotation
	profile      *BrowserProfile
	tagsSent     bool // Whether DataDome tags have been sent this session
}

// NewPKCClient creates a new Pokemon Center client with the default browser profile.
// proxy should be in CapSolver format: http://user:pass@ip:port
func NewPKCClient(client tls_client.HttpClient, session *hyper.Session, logger Logger, proxy string) *PKCClient {
	return NewPKCClientWithProfile(client, session, logger, proxy, DefaultProfile)
}

// NewPKCClientWithProfile creates a new Pokemon Center client with a specific browser profile.
func NewPKCClientWithProfile(client tls_client.HttpClient, session *hyper.Session, logger Logger, proxy string, profile *BrowserProfile) *PKCClient {
	return &PKCClient{
		client:  client,
		session: session,
		logger:  logger,
		proxy:   proxy,
		profile: profile,
	}
}

// SetProxyManager sets the proxy manager for rotation support.
func (p *PKCClient) SetProxyManager(pm *ProxyManager) {
	p.proxyManager = pm
}

// RotateProxy switches to the next proxy without recreating the client.
// Uses SetProxy() to change proxy on existing client, preserving cookies and session.
// Use this for connection-based errors where the session is still valid.
// Returns true if rotation succeeded.
func (p *PKCClient) RotateProxy() bool {
	if p.proxyManager == nil {
		return false
	}

	newProxy := p.proxyManager.Rotate()
	if err := p.client.SetProxy(newProxy); err != nil {
		p.logger.Log("Failed to set new proxy: %v", err)
		return false
	}

	p.proxy = newProxy
	p.externalIP = "" // Clear cached IP since proxy changed
	p.logger.Log("Rotated proxy: %s", p.proxyManager.CurrentDisplay())
	return true
}

// RotateSession switches to a new proxy and recreates the HTTP client and session.
// Clears all state (cookies, session, headers). Use for non-connection errors
// like fingerprint blocks or challenges that require a fresh start.
// Returns true if rotation succeeded.
func (p *PKCClient) RotateSession() bool {
	if p.proxyManager == nil {
		return false
	}

	newProxy := p.proxyManager.Rotate()
	newClient, err := NewClient(nil, newProxy)
	if err != nil {
		p.logger.Log("Failed to create client with new proxy: %v", err)
		return false
	}

	p.client = newClient
	p.proxy = newProxy
	p.externalIP = ""             // Clear cached IP
	p.session = NewHyperSession() // Reset session
	p.headers = nil               // Clear cached headers
	p.tagsSent = false            // Reset tags flag
	p.logger.Log("Rotated session: %s", p.proxyManager.CurrentDisplay())
	return true
}

// ResetSession creates a fresh Hyper session.
// Call this when encountering session-related errors like "malformed device link".
func (p *PKCClient) ResetSession() {
	p.session = NewHyperSession()
	p.headers = nil
	p.externalIP = ""
	p.tagsSent = false
}

// doRequest executes an HTTP request and logs the request URL and response status code.
// This provides basic request/response logging for all HTTP calls.
func (p *PKCClient) doRequest(req *http.Request) (*http.Response, error) {
	resp, err := p.client.Do(req)
	if err != nil {
		p.logger.Log("%s %s -> error: %v", req.Method, req.URL.Path, err)
		return nil, err
	}
	p.logger.Log("%s %s -> %d", req.Method, req.URL.Path, resp.StatusCode)
	return resp, nil
}

// InitializeSession proactively sets up the session by generating Reese84 sensor
// and submitting DataDome tags. This should be called before making any other requests.
func (p *PKCClient) InitializeSession(ctx context.Context) error {
	// Get external IP
	ip, err := getExternalIP(p.client, p.session.ApiKey)
	if err != nil {
		return fmt.Errorf("failed to get external IP: %w", err)
	}
	p.externalIP = ip

	// Fetch base page to get dynamic values and potentially trigger challenges
	body, statusCode, err := p.makeNavigationRequest(pkcHomeURL)
	if err != nil {
		return fmt.Errorf("failed to fetch base page: %w", err)
	}

	// Check if we got a Reese84 challenge and solve it proactively
	if IsReese84Challenge(body) {
		p.logger.Log("Solving Reese84 challenge...")
		_, err := SolveReese84(ctx, p.client, p.session, pkcHomeURL, stringReader(body))
		if err != nil {
			return fmt.Errorf("failed to solve Reese84: %w", err)
		}

		// Refetch page after solving
		body, statusCode, err = p.makeNavigationRequest(pkcHomeURL)
		if err != nil {
			return fmt.Errorf("failed to refetch page: %w", err)
		}
	}

	// Assert session - check for additional challenges
	if err := p.assertSession(ctx, body, statusCode); err != nil {
		return fmt.Errorf("session assertion failed: %w", err)
	}

	// Submit DataDome tags per Hyper documentation:
	// "Posting tags should be done twice... First with type 'ch' and the second time with type 'le'"
	// Only do this once per session to minimize API costs
	if !p.tagsSent {
		p.logger.Log("Submitting DataDome tags ('ch' + 'le')...")
		// First 'ch' tag - updates datadome cookie
		if err := p.SubmitDataDomeTag(ctx, pkcHomeURL, "ch"); err != nil {
			p.logger.Log("DataDome 'ch' tag warning: %v", err)
		}
		// Second 'le' tag - using the cookie from 'ch' response
		if err := p.SubmitDataDomeTag(ctx, pkcHomeURL, "le"); err != nil {
			p.logger.Log("DataDome 'le' tag warning: %v", err)
		}
		p.tagsSent = true
	}

	return nil
}

// assertSession validates the session by checking for and handling any challenges.
func (p *PKCClient) assertSession(ctx context.Context, body string, statusCode int) error {
	// Check for DataDome interstitial (403 with captcha-delivery script)
	if statusCode == 403 && IsDataDomeInterstitial(statusCode, body) {
		p.logger.Log("DataDome interstitial detected, solving...")
		headers, err := SolveDataDomeInterstitial(ctx, p.client, p.session, pkcHomeURL, body, p.logger)
		if err != nil {
			return fmt.Errorf("failed to solve DataDome interstitial: %w", err)
		}
		if headers != nil {
			p.headers = headers
			p.logger.Log("Got headers from Hyper API (FullVersionList: %s)", headers.FullVersionList)
		}
		return nil
	}

	// Check for DataDome slider challenge
	if statusCode == 403 && strings.Contains(body, "ct.captcha-delivery.com/c.js") {
		p.logger.Log("DataDome slider challenge detected")
		// For now, return error - slider handling can be added later
		return fmt.Errorf("DataDome slider challenge not yet implemented")
	}

	// Check for Incapsula queue
	if strings.Contains(body, "Incapsula_Resource") {
		p.logger.Log("Incapsula queue detected")
		// Queue handling would go here
		return fmt.Errorf("Incapsula queue handling not yet implemented")
	}

	// Check we got a valid page
	if statusCode != 200 {
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}

	return nil
}

// SubmitDataDomeTag submits a single DataDome tag with the specified type ('ch' or 'le').
func (p *PKCClient) SubmitDataDomeTag(ctx context.Context, referer, tagType string) error {
	parsedURL, err := url.Parse(referer)
	if err != nil {
		return err
	}

	datadomeCookie := getDatadomeCookie(p.client, parsedURL)
	if datadomeCookie == "" {
		// If no datadome cookie, use "null" as per working example
		datadomeCookie = "null"
	}

	// Get IP if not cached
	if p.externalIP == "" {
		ip, err := getExternalIP(p.client, p.session.ApiKey)
		if err != nil {
			return fmt.Errorf("failed to get external IP: %w", err)
		}
		p.externalIP = ip
	}

	newCookie, err := submitDataDomeTags(ctx, p.client, p.session, referer, datadomeCookie, p.externalIP, tagType)
	if err != nil {
		return err
	}

	if newCookie != "" {
		setDatadomeCookie(p.client, parsedURL, newCookie)
	}

	return nil
}

// CartAuthResponse represents the auth token set by the cart data endpoint.
type CartAuthResponse struct {
	AccessToken string   `json:"access_token"`
	TokenType   string   `json:"token_type"`
	ExpiresIn   int      `json:"expires_in"`
	Scope       string   `json:"scope"`
	Role        string   `json:"role"`
	Roles       []string `json:"roles"`
	ID          int64    `json:"id"`
}

// EmailSignupRequest represents the request body for email signup.
type EmailSignupRequest struct {
	Email      string            `json:"email"`
	DOB        string            `json:"dob"`
	Region     string            `json:"region"`
	Source     EmailSignupSource `json:"source"`
	EmailLists []string          `json:"email_lists"`
}

// EmailSignupSource represents the source info for email signup.
type EmailSignupSource struct {
	BaseURL          string `json:"base_url"`
	EngagementSource string `json:"engagement_source"`
	UTMSource        string `json:"utm_source"`
	UTMMedium        string `json:"utm_medium"`
	UTMCampaign      string `json:"utm_campaign"`
	UTMTerm          string `json:"utm_term"`
	UTMContent       string `json:"utm_content"`
}

// GetHomepage fetches the Pokemon Center homepage, handling Reese84 and DataDome challenges.
func (p *PKCClient) GetHomepage(ctx context.Context) (string, error) {
	return p.GetPage(ctx, pkcHomeURL)
}

// GetCartAuth fetches the cart data endpoint to obtain an auth token cookie.
// This should be called after successfully loading the homepage with cookies set.
func (p *PKCClient) GetCartAuth(ctx context.Context) (*CartAuthResponse, error) {
	for range maxChallengeRetries {
		auth, needsRetry, err := p.doGetCartAuth(ctx)
		if err != nil {
			return nil, err
		}
		if !needsRetry {
			return auth, nil
		}
	}
	return nil, fmt.Errorf("GetCartAuth: max challenge retries (%d) exceeded", maxChallengeRetries)
}

func (p *PKCClient) doGetCartAuth(ctx context.Context) (*CartAuthResponse, bool, error) {
	req, err := http.NewRequest(http.MethodGet, pkcCartDataURL, nil)
	if err != nil {
		return nil, false, err
	}

	req.Header = http.Header{
		"Host":               {"www.pokemoncenter.com"},
		"Connection":         {"keep-alive"},
		"X-Store-Scope":      {"pokemon"},
		"sec-ch-ua-platform": {`"Windows"`},
		"sec-ch-ua":          {p.profile.SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"User-Agent":         {p.profile.UserAgent},
		"accept":             {"application/json"},
		"Accept-Version":     {"1"},
		"Content-Type":       {"application/json"},
		"Sec-Fetch-Site":     {"same-origin"},
		"Sec-Fetch-Mode":     {"cors"},
		"Sec-Fetch-Dest":     {"empty"},
		"Referer":            {pkcHomeURL},
		"Accept-Encoding":    {"gzip, deflate, br, zstd"},
		"Accept-Language":    {"en-US,en;q=0.9"},
		http.HeaderOrderKey: {
			"Host",
			"Connection",
			"X-Store-Scope",
			"sec-ch-ua-platform",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"User-Agent",
			"accept",
			"Accept-Version",
			"Content-Type",
			"Sec-Fetch-Site",
			"Sec-Fetch-Mode",
			"Sec-Fetch-Dest",
			"Referer",
			"Accept-Encoding",
			"Accept-Language",
			"Cookie",
		},
		http.PHeaderOrderKey: PseudoHeaderOrder,
	}

	resp, err := p.doRequest(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	// The auth token is set via Set-Cookie header, parse it from the cookie jar
	// The cookie value is URL-encoded JSON
	bodyBytes, err := readResponseBody(resp)
	if err != nil {
		return nil, false, err
	}

	// Check for protection challenges on non-200 responses
	if resp.StatusCode != 200 {
		solved, err := p.handleBadResponse(ctx, resp.StatusCode, bodyBytes, pkcCartDataURL)
		if err != nil {
			return nil, false, err
		}
		if solved {
			return nil, true, nil // Signal retry needed
		}
	}

	// Extract auth cookie from the response cookies
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "auth" {
			var auth CartAuthResponse
			if err := json.Unmarshal([]byte(cookie.Value), &auth); err != nil {
				return nil, false, fmt.Errorf("failed to parse auth cookie: %w", err)
			}
			return &auth, false, nil
		}
	}

	// If no new auth cookie in response, check the cookie jar for existing one
	cookieURL, _ := url.Parse(pkcBaseURL)
	for _, cookie := range p.client.GetCookies(cookieURL) {
		if cookie.Name == "auth" {
			var auth CartAuthResponse
			if err := json.Unmarshal([]byte(cookie.Value), &auth); err != nil {
				return nil, false, fmt.Errorf("failed to parse auth cookie from jar: %w", err)
			}
			return &auth, false, nil
		}
	}

	return nil, false, fmt.Errorf("no auth cookie in response or jar (status %d)", resp.StatusCode)
}

// ProfileDataResponse represents the response from the profile data endpoint.
type ProfileDataResponse struct {
	Role string `json:"role"`
	ID   int64  `json:"id"`
}

// GetProfileData fetches the profile data endpoint to establish session identity.
// This should be called after GetCartAuth and before email signup.
func (p *PKCClient) GetProfileData(ctx context.Context) (*ProfileDataResponse, error) {
	for range maxChallengeRetries {
		profile, needsRetry, err := p.doGetProfileData(ctx)
		if err != nil {
			return nil, err
		}
		if !needsRetry {
			return profile, nil
		}
	}
	return nil, fmt.Errorf("GetProfileData: max challenge retries (%d) exceeded", maxChallengeRetries)
}

func (p *PKCClient) doGetProfileData(ctx context.Context) (*ProfileDataResponse, bool, error) {
	req, err := http.NewRequest(http.MethodGet, pkcProfileDataURL, nil)
	if err != nil {
		return nil, false, err
	}

	req.Header = http.Header{
		"Host":               {"www.pokemoncenter.com"},
		"Connection":         {"keep-alive"},
		"X-Store-Scope":      {"pokemon"},
		"sec-ch-ua-platform": {`"Windows"`},
		"sec-ch-ua":          {p.profile.SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"User-Agent":         {p.profile.UserAgent},
		"accept":             {"application/json"},
		"Accept-Version":     {"1"},
		"Content-Type":       {"application/json"},
		"Sec-Fetch-Site":     {"same-origin"},
		"Sec-Fetch-Mode":     {"cors"},
		"Sec-Fetch-Dest":     {"empty"},
		"Referer":            {pkcHomeURL},
		"Accept-Encoding":    {"gzip, deflate, br, zstd"},
		"Accept-Language":    {"en-US,en;q=0.9"},
		http.HeaderOrderKey: {
			"Host",
			"Connection",
			"X-Store-Scope",
			"sec-ch-ua-platform",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"User-Agent",
			"accept",
			"Accept-Version",
			"Content-Type",
			"Sec-Fetch-Site",
			"Sec-Fetch-Mode",
			"Sec-Fetch-Dest",
			"Referer",
			"Accept-Encoding",
			"Accept-Language",
			"Cookie",
		},
		http.PHeaderOrderKey: PseudoHeaderOrder,
	}

	resp, err := p.doRequest(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	bodyBytes, err := readResponseBody(resp)
	if err != nil {
		return nil, false, err
	}

	// Check for protection challenges on non-200 responses
	if resp.StatusCode != 200 {
		solved, err := p.handleBadResponse(ctx, resp.StatusCode, bodyBytes, pkcProfileDataURL)
		if err != nil {
			return nil, false, err
		}
		if solved {
			return nil, true, nil // Signal retry needed
		}
	}

	var profile ProfileDataResponse
	if err := json.Unmarshal(bodyBytes, &profile); err != nil {
		return nil, false, fmt.Errorf("failed to parse profile response: %w (body: %s)", err, string(bodyBytes))
	}

	return &profile, false, nil
}

// generateCorrelationID generates a new UUID v4 for the correlationId cookie.
func generateCorrelationID() string {
	return uuid.New().String()
}

// setEmailSignupCookies sets the correlationId cookie required for email signup.
// Returns the generated correlationID.
func setEmailSignupCookies(client tls_client.HttpClient) string {
	correlationID := generateCorrelationID()
	cookieURL, _ := url.Parse(pkcBaseURL)

	// Only set correlationId - the amp cookies weren't in the working Charles capture
	client.SetCookies(cookieURL, []*http.Cookie{
		{
			Name:   "correlationId",
			Value:  correlationID,
			Domain: ".pokemoncenter.com",
			Path:   "/",
		},
	})

	return correlationID
}

// EmailSignup signs up an email to the Pokemon Center newsletter.
// Returns the email address that was signed up.
func (p *PKCClient) EmailSignup(ctx context.Context, captchaAPIKey, email string) (string, error) {
	// Generate and set correlation and Amplitude cookies
	setEmailSignupCookies(p.client)

	// Generate random DOB
	dob := GenerateRandomDOOB()

	p.logger.Log("Signing up: %s", email)

	// Send tracking event (this sets SSRT and SSOD cookies required for signup)
	p.sendEmailSignupTrackingEvent()

	// Build request body
	payload := map[string]any{
		"email":  email,
		"dob":    dob,
		"region": "US",
		"source": map[string]string{
			"base_url":          "/",
			"engagement_source": "pcenter",
			"utm_source":        "",
			"utm_medium":        "",
			"utm_campaign":      "",
			"utm_term":          "",
			"utm_content":       "",
		},
		"email_lists": []string{"pcenter"},
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal signup payload: %w", err)
	}
	bodyStr := string(bodyBytes)

	// Solve reCAPTCHA v3 (proxyless)
	p.logger.Log("Solving reCAPTCHA...")
	captchaToken, captchaErr := Get2CaptchaRecapV3Solution(captchaAPIKey, pkcHomeURL, pkcRecaptchaSiteKey, "submit", 0.3)
	if captchaErr != nil {
		return "", fmt.Errorf("failed to solve recaptcha: %w", captchaErr)
	}

	// Refresh cart auth and profile data
	if _, err := p.GetCartAuth(ctx); err != nil {
		return "", fmt.Errorf("failed to refresh cart auth: %w", err)
	}
	if _, err := p.GetProfileData(ctx); err != nil {
		return "", fmt.Errorf("failed to refresh profile data: %w", err)
	}

	p.sendEmailSignupTrackingEvent()

	// Submit signup request with retry handling for connection errors and captcha score failures
	success, err := p.submitEmailSignup(ctx, captchaAPIKey, bodyStr, captchaToken)
	if err != nil {
		return "", err
	}
	if success {
		return email, nil
	}

	return "", fmt.Errorf("signup failed")
}

// submitEmailSignup sends the actual signup request. Returns (success, error).
// Handles connection errors with proxy-only rotation (up to maxSignupProxyRetries times)
// and captcha score errors with new token fetches (up to maxCaptchaRetries times).
func (p *PKCClient) submitEmailSignup(ctx context.Context, captchaAPIKey, bodyStr, captchaToken string) (bool, error) {
	currentToken := captchaToken
	captchaRetries := 0
	proxyRetries := 0

	for range maxChallengeRetries {
		success, needsRetry, err := p.doSubmitEmailSignup(ctx, bodyStr, currentToken)

		// Keep handling recoverable errors until we succeed or exhaust retries
		for err != nil {
			// Handle captcha score too low - fetch new token and retry
			if errors.Is(err, ErrCaptchaScoreTooLow) {
				if captchaRetries >= maxCaptchaRetries {
					return false, err // Exhausted captcha retries
				}
				captchaRetries++
				p.logger.Log("Captcha score too low, fetching new token (attempt %d/%d)",
					captchaRetries, maxCaptchaRetries)

				newToken, captchaErr := Get2CaptchaRecapV3Solution(captchaAPIKey, pkcHomeURL, pkcRecaptchaSiteKey, "submit", 0.3)
				if captchaErr != nil {
					p.logger.Log("Failed to get new captcha token: %v", captchaErr)
					continue // Try fetching token again
				}

				currentToken = newToken
				success, needsRetry, err = p.doSubmitEmailSignup(ctx, bodyStr, currentToken)
				continue // Check the new error
			}

			// Handle connection errors with proxy-only rotation
			if IsRetryableError(err) {
				if proxyRetries >= maxSignupProxyRetries {
					return false, err // Exhausted proxy retries
				}
				proxyRetries++
				p.logger.Log("Connection error on signup, rotating proxy (attempt %d/%d): %v",
					proxyRetries, maxSignupProxyRetries, err)

				if !p.RotateProxy() {
					return false, fmt.Errorf("failed to rotate proxy: %w", err)
				}

				success, needsRetry, err = p.doSubmitEmailSignup(ctx, bodyStr, currentToken)
				continue // Check the new error
			}

			// Non-recoverable error
			return false, err
		}

		if !needsRetry {
			return success, nil
		}
	}
	return false, fmt.Errorf("submitEmailSignup: max challenge retries (%d) exceeded", maxChallengeRetries)
}

func (p *PKCClient) doSubmitEmailSignup(ctx context.Context, bodyStr, captchaToken string) (bool, bool, error) {
	bodyBytes := []byte(bodyStr)

	req, err := http.NewRequest(http.MethodPost, pkcEmailSignupURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return false, false, err
	}

	// Headers matching browser exactly - NO extra sec-ch-ua headers
	// Browser only sends: sec-ch-ua-platform, sec-ch-ua, sec-ch-ua-mobile
	req.Header = http.Header{
		"Host":               {"www.pokemoncenter.com"},
		"Connection":         {"keep-alive"},
		"sec-ch-ua-platform": {`"Windows"`},
		"x-recaptcha-token":  {captchaToken},
		"sec-ch-ua":          {p.profile.SecChUa},
		"Content-Type":       {"text/plain;charset=UTF-8"},
		"sec-ch-ua-mobile":   {"?0"},
		"User-Agent":         {p.profile.UserAgent},
		"Accept":             {"*/*"},
		"Origin":             {pkcBaseURL},
		"Sec-Fetch-Site":     {"same-origin"},
		"Sec-Fetch-Mode":     {"cors"},
		"Sec-Fetch-Dest":     {"empty"},
		"Referer":            {pkcHomeURL},
		"Accept-Encoding":    {"gzip, deflate, br, zstd"},
		"Accept-Language":    {"en-US,en;q=0.9"},
		http.HeaderOrderKey: {
			"Host",
			"Connection",
			"Content-Length",
			"sec-ch-ua-platform",
			"x-recaptcha-token",
			"sec-ch-ua",
			"Content-Type",
			"sec-ch-ua-mobile",
			"User-Agent",
			"Accept",
			"Origin",
			"Sec-Fetch-Site",
			"Sec-Fetch-Mode",
			"Sec-Fetch-Dest",
			"Referer",
			"Accept-Encoding",
			"Accept-Language",
			"Cookie",
		},
		http.PHeaderOrderKey: PseudoHeaderOrder,
	}

	resp, err := p.doRequest(req)
	if err != nil {
		return false, false, err
	}
	defer resp.Body.Close()

	respBodyBytes, err := readResponseBody(resp)
	if err != nil {
		return false, false, err
	}

	// Check for protection challenges
	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		// Check for captcha score failure (403 with specific message)
		if resp.StatusCode == 403 && strings.Contains(string(respBodyBytes), "identity-based policy") {
			return false, false, ErrCaptchaScoreTooLow
		}

		solved, err := p.handleBadResponse(ctx, resp.StatusCode, respBodyBytes, pkcEmailSignupURL)
		if err != nil {
			return false, false, err
		}
		if solved {
			return false, true, nil // Signal retry needed
		}
		return false, false, fmt.Errorf("unhandled %d response: %s", resp.StatusCode, string(respBodyBytes))
	}

	// 204 No Content means success
	if resp.StatusCode == 204 {
		p.logger.Log("Email signup successful!")
		return true, false, nil
	}

	return false, false, fmt.Errorf("unexpected response status: %d", resp.StatusCode)
}

// handleBadResponse checks for and solves protection challenges in error responses.
// Returns (solved, error) - if solved is true, the caller should retry the request.
func (p *PKCClient) handleBadResponse(ctx context.Context, statusCode int, body []byte, referer string) (bool, error) {
	bodyStr := string(body)

	// Check for Reese84 challenge first (can appear on any status code including 400)
	if IsReese84Challenge(bodyStr) {
		p.logger.Log("Reese84 challenge detected, solving...")
		_, err := SolveReese84(ctx, p.client, p.session, referer, stringReader(bodyStr))
		if err != nil {
			return false, fmt.Errorf("failed to solve Reese84: %w", err)
		}
		return true, nil
	}

	// Handle 403 responses
	if statusCode == 403 {
		// Check for JSON-based DataDome challenge (API responses return JSON with URL)
		var ddResp struct {
			URL string `json:"url"`
		}
		if json.Unmarshal(body, &ddResp) == nil && ddResp.URL != "" {
			p.logger.Log("DataDome JSON challenge detected, solving...")
			if err := p.solveDataDomeJSONChallenge(ctx, ddResp.URL, referer); err != nil {
				return false, fmt.Errorf("failed to solve DataDome JSON challenge: %w", err)
			}
			return true, nil
		}

		// Check for HTML-based DataDome interstitial
		if IsDataDomeInterstitial(statusCode, bodyStr) {
			p.logger.Log("DataDome HTML interstitial detected, solving...")
			headers, err := SolveDataDomeInterstitial(ctx, p.client, p.session, referer, bodyStr, p.logger)
			if err != nil {
				return false, fmt.Errorf("failed to solve DataDome interstitial: %w", err)
			}
			if headers != nil {
				p.headers = headers
			}
			return true, nil
		}

		// Check for DataDome fingerprint enforcement block
		// This indicates a fundamental fingerprint mismatch - retrying won't help
		if IsDataDomeFingerprintBlock(statusCode, bodyStr) {
			p.logger.Log("DataDome fingerprint block detected - session fingerprint rejected")
			return false, fmt.Errorf("DataDome fingerprint block: session fingerprint rejected (possible Chrome version mismatch between captcha solver and request)")
		}

		// Unknown 403
		preview := bodyStr
		if len(preview) > 500 {
			preview = preview[:500]
		}
		return false, fmt.Errorf("unhandled 403 response: %s", preview)
	}

	// Unhandled status code
	preview := bodyStr
	if len(preview) > 500 {
		preview = preview[:500]
	}
	return false, fmt.Errorf("unhandled response (status %d): %s", statusCode, preview)
}

// solveDataDomeJSONChallenge handles DataDome challenges returned as JSON (API responses).
// The deviceLink is the full URL from the JSON response's "url" field.
func (p *PKCClient) solveDataDomeJSONChallenge(ctx context.Context, deviceLink, referer string) error {
	// Retry once if we get a session corruption error
	for range 2 {
		err := p.doSolveDataDomeJSONChallenge(ctx, deviceLink, referer)
		if err == nil {
			return nil
		}

		// Check if it's a session corruption error
		if strings.Contains(err.Error(), "malformed device link") || strings.Contains(err.Error(), "missing html") {
			p.logger.Log("Session corrupted, rotating session...")
			// Rotate session to get fresh HTTP client + session (not just proxy)
			if p.RotateSession() {
				// Re-initialize session with new proxy
				if initErr := p.InitializeSession(ctx); initErr != nil {
					p.logger.Log("WARNING: Session re-init failed: %v", initErr)
				}
			} else {
				// No proxy manager, just reset session
				p.ResetSession()
			}
			continue
		}

		return err
	}
	return fmt.Errorf("failed to solve DataDome challenge after retry")
}

// doSolveDataDomeJSONChallenge performs the actual DataDome challenge solving.
func (p *PKCClient) doSolveDataDomeJSONChallenge(ctx context.Context, deviceLink, referer string) error {
	// Fetch the device check page
	deviceHTML, err := fetchDeviceCheckPage(p.client, deviceLink, referer)
	if err != nil {
		return fmt.Errorf("failed to fetch device check page: %w", err)
	}

	// Get external IP
	externalIP, err := getExternalIP(p.client, p.session.ApiKey)
	if err != nil {
		return fmt.Errorf("failed to get external IP: %w", err)
	}

	// Generate the interstitial payload using Hyper API
	payload, headers, err := p.session.GenerateDataDomeInterstitial(ctx, &hyper.DataDomeInterstitialInput{
		UserAgent:      p.profile.UserAgent,
		DeviceLink:     deviceLink,
		Html:           deviceHTML,
		AcceptLanguage: "en-US",
		IP:             externalIP,
	})
	if err != nil {
		return fmt.Errorf("failed to generate interstitial payload: %w", err)
	}

	// Capture headers from Hyper API for use in subsequent requests
	if headers != nil {
		p.headers = headers
	}

	// POST the payload to solve the challenge
	resp, err := submitInterstitialPayload(p.client, deviceLink, payload)
	if err != nil {
		return fmt.Errorf("failed to submit interstitial payload: %w", err)
	}

	// Update the datadome cookie
	if resp.Cookie != "" {
		newCookieValue := extractCookieValue(resp.Cookie)
		setDatadomeCookieForHost(p.client, pkcBaseURL, newCookieValue)
	}

	return nil
}

// sendEmailSignupTrackingEvent sends the tracking event that must occur before email signup.
// This request sets SSRT and SSOD cookies that are required for the signup to succeed.
func (p *PKCClient) sendEmailSignupTrackingEvent() error {

	// Build tracking URL with timestamp
	timestamp := time.Now().UnixMilli()
	trackingURL := fmt.Sprintf("%s/__ssobj/track?event=email_signup_click&value=undefined&x=%d-1", pkcBaseURL, timestamp)

	req, err := http.NewRequest(http.MethodGet, trackingURL, nil)
	if err != nil {
		return err
	}

	req.Header = http.Header{
		"Host":               {"www.pokemoncenter.com"},
		"Connection":         {"keep-alive"},
		"sec-ch-ua-platform": {`"Windows"`},
		"sec-ch-ua":          {p.profile.SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"X-Requested-With":   {"XMLHttpRequest"},
		"User-Agent":         {p.profile.UserAgent},
		"Accept":             {"*/*"},
		"Sec-Fetch-Site":     {"same-origin"},
		"Sec-Fetch-Mode":     {"cors"},
		"Sec-Fetch-Dest":     {"empty"},
		"Referer":            {pkcHomeURL},
		"Accept-Encoding":    {"gzip, deflate, br, zstd"},
		"Accept-Language":    {"en-US,en;q=0.9"},
		http.HeaderOrderKey: {
			"Host",
			"Connection",
			"sec-ch-ua-full-version-list",
			"sec-ch-ua-platform",
			"sec-ch-ua",
			"sec-ch-ua-model",
			"sec-ch-device-memory",
			"sec-ch-ua-mobile",
			"sec-ch-ua-arch",
			"X-Requested-With",
			"User-Agent",
			"Accept",
			"Sec-Fetch-Site",
			"Sec-Fetch-Mode",
			"Sec-Fetch-Dest",
			"Referer",
			"Accept-Encoding",
			"Accept-Language",
		},
		http.PHeaderOrderKey: PseudoHeaderOrder,
	}

	// Only add optional sec-ch-ua headers if Hyper API provided them
	if p.headers != nil {
		if p.headers.FullVersionList != "" {
			req.Header.Set("sec-ch-ua-full-version-list", p.headers.FullVersionList)
		}
		if p.headers.Model != "" {
			req.Header.Set("sec-ch-ua-model", p.headers.Model)
		}
		if p.headers.DeviceMemory != "" {
			req.Header.Set("sec-ch-device-memory", p.headers.DeviceMemory)
		}
		if p.headers.Arch != "" {
			req.Header.Set("sec-ch-ua-arch", p.headers.Arch)
		}
	}

	resp, err := p.doRequest(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Read and discard body
	io.Copy(io.Discard, resp.Body)
	return nil
}

// GetPage fetches a page from Pokemon Center, handling all protection challenges.
// Note: InitializeSession should be called before this method to set up the session.
func (p *PKCClient) GetPage(ctx context.Context, pageURL string) (string, error) {
	// Initial request
	body, statusCode, err := p.makeNavigationRequest(pageURL)
	if err != nil {
		return "", fmt.Errorf("initial request failed: %w", err)
	}

	// Handle protection challenges - retry up to 3 times
	for range 3 {
		needsRetry := false

		// Check for challenges (Reese84 can appear on 200, DataDome on 403)
		if statusCode != 200 || IsReese84Challenge(body) {
			solved, err := p.handleBadResponse(ctx, statusCode, []byte(body), pageURL)
			if err != nil {
				return "", err
			}
			needsRetry = solved
		}

		if !needsRetry {
			break
		}

		// Retry the request
		body, statusCode, err = p.makeNavigationRequest(pageURL)
		if err != nil {
			return "", fmt.Errorf("retry request failed: %w", err)
		}
	}

	// Final check - should have valid response now
	if statusCode != 200 {
		return "", fmt.Errorf("still getting status %d after retries", statusCode)
	}
	if IsReese84Challenge(body) {
		return "", fmt.Errorf("still getting Reese84 challenge after solving")
	}

	// DataDome tags are already sent during InitializeSession, no need to send again here

	return body, nil
}

// makeNavigationRequest makes a browser-like navigation request.
func (p *PKCClient) makeNavigationRequest(targetURL string) (string, int, error) {
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return "", 0, err
	}

	req.Header = http.Header{
		"upgrade-insecure-requests": {"1"},
		"user-agent":                {p.profile.UserAgent},
		"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"sec-fetch-site":            {"none"},
		"sec-fetch-mode":            {"navigate"},
		"sec-fetch-user":            {"?1"},
		"sec-fetch-dest":            {"document"},
		"sec-ch-ua":                 {p.profile.SecChUa},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {`"Windows"`},
		"accept-encoding":           {"gzip, deflate, br, zstd"},
		"accept-language":           {"en-US,en;q=0.9"},
		http.HeaderOrderKey: {
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"accept-encoding",
			"accept-language",
		},
		http.PHeaderOrderKey: PseudoHeaderOrder,
	}

	resp, err := p.doRequest(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	bodyBytes, err := readResponseBody(resp)
	if err != nil {
		return "", resp.StatusCode, err
	}

	return string(bodyBytes), resp.StatusCode, nil
}

// stringReader creates an io.Reader from a string.
func stringReader(s string) io.Reader {
	return &stringReaderImpl{s: s, i: 0}
}

type stringReaderImpl struct {
	s string
	i int
}

func (r *stringReaderImpl) Read(p []byte) (n int, err error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	n = copy(p, r.s[r.i:])
	r.i += n
	return n, nil
}
