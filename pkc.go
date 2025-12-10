package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/url"
	"strings"
	"time"

	"github.com/Hyper-Solutions/hyper-sdk-go/v2"
	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/google/uuid"
)

const (
	pkcBaseURL           = "https://www.pokemoncenter.com"
	pkcHomeURL           = pkcBaseURL + "/"
	pkcCartDataURL       = pkcBaseURL + "/tpci-ecommweb-api/cart/data?type=mini"
	pkcProfileDataURL    = pkcBaseURL + "/tpci-ecommweb-api/profile/data?checkRole=true"
	pkcEmailSignupURL    = pkcBaseURL + "/tpci-ecommweb-api/email/signup"
	pkcRecaptchaSiteKey  = "6Lc4P0MoAAAAAAhyCYBhoVfHZUF3HMvFdXSRZ-kO"
	pkcRecaptchaMinScore = 0.7
	pkcReese84ScriptPath = "/vice-come-Soldenyson-it-non-Banquoh-Chare-Hart-C"

	pkcUseTwoCaptcha  = true
	pkcUseCapmonster  = false
	pkcUseCapsolver   = false
	pkcEnableTracking = false

	maxProxyRetries        = 5
	maxChallengeRetries    = 3
	captchaRotateThreshold = 5
	maxSessionRotations    = 5
)

type PKCClient struct {
	client       tls_client.HttpClient
	session      *hyper.Session
	logger       Logger
	externalIP   string
	headers      *hyper.Headers
	proxy        string
	proxyManager *ProxyManager
	profile      *BrowserProfile
	tagsSent     bool

	reese84Challenges   int
	ddInterstitials     int
	ddJSONChallenges    int
	ddFingerprintBlocks int
	sessionRotations    int
	proxyRotations      int
}

func NewPKCClient(client tls_client.HttpClient, session *hyper.Session, logger Logger, proxy string) *PKCClient {
	return NewPKCClientWithProfile(client, session, logger, proxy, DefaultProfile)
}

func NewPKCClientWithProfile(client tls_client.HttpClient, session *hyper.Session, logger Logger, proxy string, profile *BrowserProfile) *PKCClient {
	return &PKCClient{
		client:  client,
		session: session,
		logger:  logger,
		proxy:   proxy,
		profile: profile,
	}
}

func (p *PKCClient) SetProxyManager(pm *ProxyManager) {
	p.proxyManager = pm
}

func (p *PKCClient) RotateProxy() bool {
	if p.proxyManager == nil {
		return false
	}

	newProxy := p.proxyManager.Rotate()
	if err := p.client.SetProxy(newProxy); err != nil {
		p.logger.Log("[SESSION] Proxy rotation FAILED: %v", err)
		return false
	}

	p.proxy = newProxy
	p.externalIP = ""
	p.proxyRotations++
	p.logger.Log("[SESSION] Proxy rotated (total: %d) -> %s", p.proxyRotations, p.proxyManager.CurrentDisplay())
	return true
}

func (p *PKCClient) RotateSession() bool {
	if p.proxyManager == nil {
		return false
	}

	newProxy := p.proxyManager.Rotate()
	newClient, err := NewClient(nil, newProxy)
	if err != nil {
		p.logger.Log("[SESSION] Session rotation FAILED: %v", err)
		return false
	}

	p.client = newClient
	p.proxy = newProxy
	p.externalIP = ""
	p.session = NewHyperSession()
	p.headers = nil
	p.tagsSent = false
	p.sessionRotations++
	p.logger.Log("[SESSION] Full session rotated (total: %d) -> %s", p.sessionRotations, p.proxyManager.CurrentDisplay())
	return true
}

func (p *PKCClient) ResetSession() {
	p.session = NewHyperSession()
	p.headers = nil
	p.externalIP = ""
	p.tagsSent = false
}

func (p *PKCClient) ReinitializeSession(ctx context.Context) error {
	if !p.RotateSession() {
		return fmt.Errorf("session rotation failed (no proxy manager)")
	}

	p.reese84Challenges = 0
	p.ddInterstitials = 0
	p.ddJSONChallenges = 0
	p.ddFingerprintBlocks = 0

	p.logger.Log("[SESSION] Reinitializing new session...")
	if err := p.InitializeSession(ctx); err != nil {
		return fmt.Errorf("session init failed after rotation: %w", err)
	}

	return nil
}

func (p *PKCClient) doRequest(req *http.Request) (*http.Response, error) {
	resp, err := p.client.Do(req)
	if err != nil {
		p.logger.Log("%s %s -> error: %v", req.Method, req.URL.Path, err)
		return nil, err
	}
	p.logger.Log("%s %s -> %d", req.Method, req.URL.Path, resp.StatusCode)
	return resp, nil
}

func (p *PKCClient) InitializeSession(ctx context.Context) error {
	p.logger.Log("[INIT] proxy=%s", p.proxyManager.CurrentDisplay())

	p.logger.Log("[INIT] [1/5] Resolving external IP...")
	ip, err := getExternalIP(p.proxy, p.session.ApiKey)
	if err != nil {
		p.logger.Log("[INIT] ✗ External IP resolution failed: %v", err)
		return fmt.Errorf("failed to get external IP: %w", err)
	}
	p.externalIP = ip
	p.logger.Log("[INIT] ✓ External IP: %s", ip)

	p.logger.Log("[INIT] [2/5] Solving static Reese84 challenge...")
	_, err = SolveStaticReese84(ctx, p.client, p.session, pkcBaseURL, p.proxy, pkcReese84ScriptPath, p.profile)
	if err != nil {
		p.logger.Log("[INIT] ✗ Static Reese84 failed: %v", err)
		return fmt.Errorf("failed to solve static Reese84: %w", err)
	}
	p.logger.Log("[INIT] ✓ Static Reese84 solved")

	p.logger.Log("[INIT] [3/5] Fetching homepage...")
	body, statusCode, err := p.makeNavigationRequest(pkcHomeURL)
	if err != nil {
		p.logger.Log("[INIT] ✗ Homepage fetch failed: %v", err)
		return fmt.Errorf("failed to fetch base page: %w", err)
	}
	p.logger.Log("[INIT] ✓ Homepage received: status=%d size=%dB", statusCode, len(body))

	if IsReese84Challenge(body) {
		p.reese84Challenges++
		p.logger.Log("[INIT] ⚠ Reese84 challenge detected on homepage (r84_count=%d)", p.reese84Challenges)
		_, err := SolveReese84(ctx, p.client, p.session, pkcHomeURL, p.proxy, stringReader(body), p.profile)
		if err != nil {
			p.logger.Log("[INIT] ✗ Reese84 solve failed: %v", err)
			return fmt.Errorf("failed to solve Reese84: %w", err)
		}
		p.logger.Log("[INIT] ✓ Reese84 solved")

		p.logger.Log("[INIT] Refetching homepage...")
		body, statusCode, err = p.makeNavigationRequest(pkcHomeURL)
		if err != nil {
			p.logger.Log("[INIT] ✗ Refetch failed: %v", err)
			return fmt.Errorf("failed to refetch page: %w", err)
		}
		p.logger.Log("[INIT] ✓ Homepage refetched: status=%d size=%dB", statusCode, len(body))
	} else {
		p.logger.Log("[INIT] ✓ No Reese84 challenge")
	}

	p.logger.Log("[INIT] [4/5] Validating session state...")
	if err := p.assertSession(ctx, body, statusCode); err != nil {
		p.logger.Log("[INIT] ✗ Session validation failed: %v", err)
		return fmt.Errorf("session assertion failed: %w", err)
	}
	p.logger.Log("[INIT] ✓ Session validated")

	if !p.tagsSent {
		p.logger.Log("[INIT] [5/5] Submitting DataDome tags...")
		limiter := GetHyperLimiter(3)
		limiter.Acquire()

		if err := p.submitDataDomeTagNoLock(ctx, pkcHomeURL, "ch"); err != nil {
			p.logger.Log("[INIT] ⚠ DataDome 'ch' tag failed (non-fatal): %v", err)
		} else {
			p.logger.Log("[INIT] ✓ DataDome 'ch' tag sent")
		}
		if err := p.submitDataDomeTagNoLock(ctx, pkcHomeURL, "le"); err != nil {
			p.logger.Log("[INIT] ⚠ DataDome 'le' tag failed (non-fatal): %v", err)
		} else {
			p.logger.Log("[INIT] ✓ DataDome 'le' tag sent")
		}

		limiter.Release()
		p.tagsSent = true
	} else {
		p.logger.Log("[INIT] [5/5] DataDome tags already sent")
	}

	p.logger.Log("[INIT] ✓ Initialization complete | stats=[r84=%d dd_int=%d dd_json=%d dd_fp=%d]",
		p.reese84Challenges, p.ddInterstitials, p.ddJSONChallenges, p.ddFingerprintBlocks)
	return nil
}

// assertSession validates the session by checking for and handling any challenges.
func (p *PKCClient) assertSession(ctx context.Context, body string, statusCode int) error {
	// Check for DataDome interstitial (403 with captcha-delivery script)
	if statusCode == 403 && IsDataDomeInterstitial(statusCode, body) {
		p.ddInterstitials++
		p.logger.Log("[CHALLENGE] DataDome interstitial on init (total: %d)", p.ddInterstitials)
		headers, err := SolveDataDomeInterstitial(ctx, p.client, p.session, pkcHomeURL, p.proxy, body, p.logger, p.profile)
		if err != nil {
			p.logger.Log("[CHALLENGE] DataDome interstitial FAILED: %v", err)
			return fmt.Errorf("failed to solve DataDome interstitial: %w", err)
		}
		if headers != nil {
			p.headers = headers
		}
		p.logger.Log("[CHALLENGE] DataDome interstitial solved")
		return nil
	}

	// Check for DataDome slider challenge
	if statusCode == 403 && strings.Contains(body, "ct.captcha-delivery.com/c.js") {
		p.logger.Log("[CHALLENGE] DataDome slider detected (not implemented)")
		return fmt.Errorf("DataDome slider challenge not yet implemented")
	}

	// Check for Incapsula queue
	if strings.Contains(body, "Incapsula_Resource") {
		p.logger.Log("[CHALLENGE] Incapsula queue detected (not implemented)")
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

	if p.externalIP == "" {
		ip, err := getExternalIP(p.proxy, p.session.ApiKey)
		if err != nil {
			return fmt.Errorf("failed to get external IP: %w", err)
		}
		p.externalIP = ip
	}

	newCookie, err := submitDataDomeTags(ctx, p.client, p.session, referer, datadomeCookie, p.externalIP, tagType, p.profile)
	if err != nil {
		return err
	}

	if newCookie != "" {
		setDatadomeCookie(p.client, parsedURL, newCookie)
	}

	return nil
}

// submitDataDomeTagNoLock submits a DataDome tag without acquiring the Hyper rate limiter.
// Caller must acquire and release the limiter externally.
func (p *PKCClient) submitDataDomeTagNoLock(ctx context.Context, referer, tagType string) error {
	parsedURL, err := url.Parse(referer)
	if err != nil {
		return err
	}

	datadomeCookie := getDatadomeCookie(p.client, parsedURL)
	if datadomeCookie == "" {
		datadomeCookie = "null"
	}

	if p.externalIP == "" {
		ip, err := getExternalIP(p.proxy, p.session.ApiKey)
		if err != nil {
			return fmt.Errorf("failed to get external IP: %w", err)
		}
		p.externalIP = ip
	}

	newCookie, err := submitDataDomeTagsNoLock(ctx, p.client, p.session, referer, datadomeCookie, p.externalIP, tagType, p.profile)
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

// Pre-allocated source to avoid repeated allocations
var defaultEmailSource = EmailSignupSource{
	BaseURL:          "/",
	EngagementSource: "pcenter",
}

// Pre-allocated email lists slice
var defaultEmailLists = []string{"pcenter"}

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
func (p *PKCClient) EmailSignup(ctx context.Context, captchaProvider *CaptchaProvider, email string) (string, error) {
	p.logger.Log("[SIGNUP] === Starting Email Signup ===")
	p.logger.Log("[SIGNUP] email=%s provider=%s", email, captchaProvider.Name)

	setEmailSignupCookies(p.client)

	body, err := json.Marshal(EmailSignupRequest{
		Email:      email,
		DOB:        GenerateRandomDOOB(),
		Region:     "US",
		Source:     defaultEmailSource,
		EmailLists: defaultEmailLists,
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal signup payload: %w", err)
	}

	p.logger.Log("[SIGNUP] [PRE-FLIGHT] Solving initial reCAPTCHA (provider=%s, min_score=%.1f)...", captchaProvider.Name, pkcRecaptchaMinScore)
	captchaToken, err := captchaProvider.Solve(captchaProvider.APIKey, pkcHomeURL, pkcRecaptchaSiteKey, "submit", p.proxy, p.profile.UserAgent, pkcRecaptchaMinScore)
	if err != nil {
		p.logger.Log("[SIGNUP] ✗ Captcha solve failed: %v", err)
		return "", fmt.Errorf("failed to solve recaptcha: %w", err)
	}
	p.logger.Log("[SIGNUP] ✓ Captcha token obtained")

	p.logger.Log("[SIGNUP] [PRE-FLIGHT] Refreshing cart auth...")
	if _, err := p.GetCartAuth(ctx); err != nil {
		p.logger.Log("[SIGNUP] ✗ Cart auth failed: %v", err)
		return "", fmt.Errorf("failed to refresh cart auth: %w", err)
	}
	p.logger.Log("[SIGNUP] ✓ Cart auth refreshed")

	p.sendAsmtUpdate()

	p.logger.Log("[SIGNUP] [PRE-FLIGHT] Refreshing profile data...")
	if _, err := p.GetProfileData(ctx); err != nil {
		p.logger.Log("[SIGNUP] ✗ Profile data failed: %v", err)
		return "", fmt.Errorf("failed to refresh profile data: %w", err)
	}
	p.logger.Log("[SIGNUP] ✓ Profile data refreshed")

	p.sendGAFunctionCalledEvent()
	p.logger.Log("[SIGNUP] Pre-flight checks complete, entering submission loop")

	sessionCaptchaFailures := 0
	totalCaptchaRetries := 0
	proxyRetries := 0
	attemptNum := 0

	for {
		attemptNum++
		p.sendEmailSignupTrackingEvent()

		p.logger.Log("[SIGNUP] [ATTEMPT #%d] Submitting signup request...", attemptNum)
		err := p.doSubmitEmailSignup(ctx, body, captchaToken)
		if err == nil {
			p.logger.Log("[SIGNUP] ✓ SUCCESS after %d attempts | stats=[cap_retries=%d session_rotations=%d proxy_rotations=%d challenges=[r84=%d dd_int=%d dd_json=%d dd_fp=%d]]",
				attemptNum, totalCaptchaRetries, p.sessionRotations, p.proxyRotations, p.reese84Challenges, p.ddInterstitials, p.ddJSONChallenges, p.ddFingerprintBlocks)
			return email, nil
		}

		switch {
		case errors.Is(err, ErrRetryNeeded):
			p.logger.Log("[SIGNUP] [RETRY] Challenge solved, retrying immediately...")
			continue

		case errors.Is(err, ErrCaptchaScoreTooLow):
			sessionCaptchaFailures++
			totalCaptchaRetries++
			p.logger.Log("[SIGNUP] ⚠ Captcha score too low | session_fails=%d/%d total_fails=%d",
				sessionCaptchaFailures, captchaRotateThreshold, totalCaptchaRetries)

			if sessionCaptchaFailures >= captchaRotateThreshold {
				if p.sessionRotations >= maxSessionRotations {
					p.logSignupFailure(email, totalCaptchaRetries, fmt.Errorf("max session rotations (%d) exceeded", maxSessionRotations))
					return "", fmt.Errorf("captcha failures persisted across %d sessions", maxSessionRotations)
				}

				p.logger.Log("[SIGNUP] [SESSION-ROTATE] Poor session quality detected, rotating full session (%d/%d)...",
					p.sessionRotations+1, maxSessionRotations)
				if err := p.ReinitializeSession(ctx); err != nil {
					p.logSignupFailure(email, totalCaptchaRetries, err)
					return "", err
				}
				sessionCaptchaFailures = 0

				p.logger.Log("[SIGNUP] [POST-ROTATE] Refreshing cart auth...")
				if _, err := p.GetCartAuth(ctx); err != nil {
					return "", fmt.Errorf("failed to refresh cart auth after rotation: %w", err)
				}
				p.sendAsmtUpdate()
				p.logger.Log("[SIGNUP] [POST-ROTATE] Refreshing profile data...")
				if _, err := p.GetProfileData(ctx); err != nil {
					return "", fmt.Errorf("failed to refresh profile data after rotation: %w", err)
				}
				p.sendGAFunctionCalledEvent()
				p.logger.Log("[SIGNUP] [POST-ROTATE] Session refresh complete")
			}

			p.logger.Log("[SIGNUP] [CAPTCHA-RETRY] Solving new captcha token (provider=%s, min_score=%.1f)...", captchaProvider.Name, pkcRecaptchaMinScore)
			captchaToken, err = captchaProvider.Solve(captchaProvider.APIKey, pkcHomeURL, pkcRecaptchaSiteKey, "submit", p.proxy, p.profile.UserAgent, pkcRecaptchaMinScore)
			if err != nil {
				if IsFatalError(err) {
					return "", err
				}
				return "", fmt.Errorf("failed to get new captcha: %w", err)
			}
			p.logger.Log("[SIGNUP] [CAPTCHA-RETRY] ✓ New token obtained")

		case IsRetryableError(err):
			if proxyRetries >= maxProxyRetries {
				p.logSignupFailure(email, totalCaptchaRetries, fmt.Errorf("max proxy retries (%d) exceeded: %w", maxProxyRetries, err))
				return "", err
			}
			proxyRetries++
			p.logger.Log("[SIGNUP] [PROXY-ROTATE] Connection error, rotating proxy (%d/%d) | error=%v", proxyRetries, maxProxyRetries, err)
			if !p.RotateProxy() {
				return "", fmt.Errorf("failed to rotate proxy: %w", err)
			}

		case IsFatalError(err):
			p.logger.Log("[SIGNUP] ✗ FATAL error encountered: %v", err)
			p.logSignupFailure(email, totalCaptchaRetries, err)
			return "", err

		default:
			p.logger.Log("[SIGNUP] ✗ Unknown error: %v", err)
			p.logSignupFailure(email, totalCaptchaRetries, err)
			return "", err
		}
	}
}

// logSignupFailure logs detailed session stats on signup failure for analysis.
func (p *PKCClient) logSignupFailure(email string, captchaRetries int, err error) {
	p.logger.Log("[SIGNUP] FAILED %s | captcha_retries=%d challenges=[r84=%d dd_int=%d dd_json=%d dd_block=%d] rotations=[proxy=%d session=%d] error=%v",
		email, captchaRetries, p.reese84Challenges, p.ddInterstitials, p.ddJSONChallenges, p.ddFingerprintBlocks,
		p.proxyRotations, p.sessionRotations, err)
}

func (p *PKCClient) doSubmitEmailSignup(ctx context.Context, body []byte, captchaToken string) error {
	req, err := http.NewRequest(http.MethodPost, pkcEmailSignupURL, bytes.NewReader(body))
	if err != nil {
		return err
	}

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
		p.logger.Log("[SIGNUP] ✗ HTTP request failed: %v", err)
		return err
	}
	defer resp.Body.Close()

	respBody, err := readResponseBody(resp)
	if err != nil {
		p.logger.Log("[SIGNUP] ✗ Failed to read response: %v", err)
		return err
	}

	p.logger.Log("[SIGNUP] Response received: status=%d size=%dB", resp.StatusCode, len(respBody))

	if resp.StatusCode == 204 {
		p.logger.Log("[SIGNUP] ✓ Accepted (204 No Content)")
		return nil
	}

	bodyStr := string(respBody)

	if resp.StatusCode == 403 && strings.Contains(bodyStr, "identity-based policy") {
		p.logger.Log("[SIGNUP] ✗ Rejected by identity-based policy (captcha score insufficient)")
		return ErrCaptchaScoreTooLow
	}

	p.logger.Log("[SIGNUP] Non-200 response, analyzing for challenges...")
	solved, err := p.handleBadResponseStr(ctx, resp.StatusCode, bodyStr, pkcEmailSignupURL)
	if err != nil {
		p.logger.Log("[SIGNUP] ✗ Challenge handling error: %v", err)
		return err
	}
	if solved {
		p.logger.Log("[SIGNUP] ✓ Challenge solved, retry needed")
		return ErrRetryNeeded
	}

	p.logger.Log("[SIGNUP] ✗ Unhandled response | status=%d body=%s", resp.StatusCode, truncate(bodyStr, 200))
	return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, bodyStr)
}

// handleBadResponse checks for and solves protection challenges in error responses.
// Returns (solved, error) - if solved is true, the caller should retry the request.
func (p *PKCClient) handleBadResponse(ctx context.Context, statusCode int, body []byte, referer string) (bool, error) {
	return p.handleBadResponseStr(ctx, statusCode, string(body), referer)
}

// handleBadResponseStr is the string variant to avoid redundant conversions when caller already has a string.
func (p *PKCClient) handleBadResponseStr(ctx context.Context, statusCode int, bodyStr, referer string) (bool, error) {
	p.logger.Log("[CHALLENGE] Analyzing response: status=%d size=%dB", statusCode, len(bodyStr))

	if IsReese84Challenge(bodyStr) {
		p.reese84Challenges++
		p.logger.Log("[CHALLENGE] ⚠ Reese84 detected | session_total=%d", p.reese84Challenges)
		_, err := SolveReese84(ctx, p.client, p.session, referer, p.proxy, stringReader(bodyStr), p.profile)
		if err != nil {
			p.logger.Log("[CHALLENGE] ✗ Reese84 solve failed: %v", err)
			return false, fmt.Errorf("failed to solve Reese84: %w", err)
		}
		p.logger.Log("[CHALLENGE] ✓ Reese84 solved successfully")
		return true, nil
	}

	if statusCode == 403 {
		var ddResp struct {
			URL string `json:"url"`
		}
		if json.Unmarshal([]byte(bodyStr), &ddResp) == nil && ddResp.URL != "" {
			p.ddJSONChallenges++
			p.logger.Log("[CHALLENGE] ⚠ DataDome JSON challenge detected | url=%s | session_total=%d", ddResp.URL, p.ddJSONChallenges)
			if err := p.solveDataDomeJSONChallenge(ctx, ddResp.URL, referer); err != nil {
				p.logger.Log("[CHALLENGE] ✗ DataDome JSON solve failed: %v", err)
				return false, fmt.Errorf("failed to solve DataDome JSON challenge: %w", err)
			}
			p.logger.Log("[CHALLENGE] ✓ DataDome JSON solved successfully")
			return true, nil
		}

		if IsDataDomeInterstitial(statusCode, bodyStr) {
			p.ddInterstitials++
			p.logger.Log("[CHALLENGE] ⚠ DataDome interstitial detected | session_total=%d", p.ddInterstitials)
			headers, err := SolveDataDomeInterstitial(ctx, p.client, p.session, referer, p.proxy, bodyStr, p.logger, p.profile)
			if err != nil {
				p.logger.Log("[CHALLENGE] ✗ DataDome interstitial solve failed: %v", err)
				return false, fmt.Errorf("failed to solve DataDome interstitial: %w", err)
			}
			if headers != nil {
				p.headers = headers
			}
			p.logger.Log("[CHALLENGE] ✓ DataDome interstitial solved successfully")
			return true, nil
		}

		if IsDataDomeFingerprintBlock(statusCode, bodyStr) {
			p.ddFingerprintBlocks++
			p.logger.Log("[CHALLENGE] ✗ DataDome fingerprint BLOCKED | session_total=%d | fingerprint_rejected", p.ddFingerprintBlocks)
			return false, fmt.Errorf("DataDome fingerprint block: session fingerprint rejected")
		}

		p.logger.Log("[CHALLENGE] ✗ Unhandled 403 response | preview=%s", truncate(bodyStr, 150))
		return false, fmt.Errorf("unhandled 403 response: %s", truncate(bodyStr, 500))
	}

	// HTTP 400 with HTML content indicates proxy/CDN issues (retryable)
	if statusCode == 400 && strings.HasPrefix(strings.TrimSpace(bodyStr), "<!DOCTYPE") {
		p.logger.Log("[CHALLENGE] HTTP 400 with HTML detected (proxy/CDN issue)")
		return false, fmt.Errorf("%w: HTTP 400 with HTML response", ErrProxyBadRequest)
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
			p.logger.Log("[SESSION] Corruption detected, rotating...")
			// Rotate session to get fresh HTTP client + session (not just proxy)
			if p.RotateSession() {
				// Re-initialize session with new proxy
				if initErr := p.InitializeSession(ctx); initErr != nil {
					p.logger.Log("[SESSION] Re-init after corruption FAILED: %v", initErr)
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
	deviceHTML, err := fetchDeviceCheckPage(p.client, deviceLink, referer, p.profile)
	if err != nil {
		return fmt.Errorf("failed to fetch device check page: %w", err)
	}

	// Get external IP
	externalIP, err := getExternalIP(p.proxy, p.session.ApiKey)
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
	resp, err := submitInterstitialPayload(p.client, deviceLink, payload, p.profile)
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

// sendAsmtUpdate sends the assessment update request that must occur before GetProfileData.
// This request sets the SSID cookie that is required for profile requests.
func (p *PKCClient) sendAsmtUpdate() error {
	if !pkcEnableTracking {
		return nil
	}

	asmtURL := pkcBaseURL + "/__ssobj/asmt_update"

	// Generate random assessment IDs (5-digit numbers)
	id1 := 10000 + rand.Intn(90000)
	id2 := 10000 + rand.Intn(90000)
	bodyJSON := []byte(fmt.Sprintf(`{"%d":true,"%d":true}`, id1, id2))

	req, err := http.NewRequest(http.MethodPost, asmtURL, bytes.NewReader(bodyJSON))
	if err != nil {
		return err
	}

	req.Header = http.Header{
		"Host":               {"www.pokemoncenter.com"},
		"Connection":         {"keep-alive"},
		"sec-ch-ua-platform": {`"Windows"`},
		"sec-ch-ua":          {p.profile.SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"User-Agent":         {p.profile.UserAgent},
		"Content-Type":       {"application/json;charset=UTF-8"},
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
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"User-Agent",
			"Content-Type",
			"Accept",
			"Origin",
			"Sec-Fetch-Site",
			"Sec-Fetch-Mode",
			"Sec-Fetch-Dest",
			"Referer",
			"Accept-Encoding",
			"Accept-Language",
		},
		http.PHeaderOrderKey: PseudoHeaderOrder,
	}

	resp, err := p.doRequest(req)
	if err != nil {
		p.logger.Log("[TRACKING] asmt_update request error (non-fatal): %v", err)
		return nil // Don't fail on tracking errors
	}
	defer resp.Body.Close()

	// Read and discard body - these tracking endpoints shouldn't return challenges
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != 200 {
		p.logger.Log("[TRACKING] asmt_update returned status %d (non-fatal)", resp.StatusCode)
	}

	return nil
}

// sendGAFunctionCalledEvent sends the tracking event after GetProfileData.
// This request sets additional session tracking cookies.
func (p *PKCClient) sendGAFunctionCalledEvent() error {
	if !pkcEnableTracking {
		return nil
	}

	// Build tracking URL with timestamp
	timestamp := time.Now().UnixMilli()
	trackingURL := fmt.Sprintf("%s/__ssobj/track?event=ss-GA-Function-Called&value=undefined&x=%d-1", pkcBaseURL, timestamp)

	req, err := http.NewRequest(http.MethodGet, trackingURL, nil)
	if err != nil {
		return err
	}

	req.Header = http.Header{
		"Host":               {"www.pokemoncenter.com"},
		"Connection":         {"keep-alive"},
		"sec-ch-ua-platform": {`"Windows"`},
		"X-Requested-With":   {"XMLHttpRequest"},
		"User-Agent":         {p.profile.UserAgent},
		"Accept":             {"*/*"},
		"sec-ch-ua":          {p.profile.SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"Sec-Fetch-Site":     {"same-origin"},
		"Sec-Fetch-Mode":     {"cors"},
		"Sec-Fetch-Dest":     {"empty"},
		"Referer":            {pkcHomeURL},
		"Accept-Encoding":    {"gzip, deflate, br, zstd"},
		"Accept-Language":    {"en-US,en;q=0.9"},
		http.HeaderOrderKey: {
			"Host",
			"Connection",
			"sec-ch-ua-platform",
			"X-Requested-With",
			"User-Agent",
			"Accept",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"Sec-Fetch-Site",
			"Sec-Fetch-Mode",
			"Sec-Fetch-Dest",
			"Referer",
			"Accept-Encoding",
			"Accept-Language",
		},
		http.PHeaderOrderKey: PseudoHeaderOrder,
	}

	resp, err := p.doRequest(req)
	if err != nil {
		p.logger.Log("[TRACKING] GA event request error (non-fatal): %v", err)
		return nil // Don't fail on tracking errors
	}
	defer resp.Body.Close()

	// Read and discard body
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		p.logger.Log("[TRACKING] GA event returned unexpected status %d (non-fatal)", resp.StatusCode)
	}

	return nil
}

// sendEmailSignupTrackingEvent sends the tracking event that must occur before email signup.
// This request sets SSRT and SSOD cookies that are required for the signup to succeed.
func (p *PKCClient) sendEmailSignupTrackingEvent() error {
	if !pkcEnableTracking {
		return nil
	}

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

// truncate returns s truncated to maxLen characters with "..." suffix if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
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
