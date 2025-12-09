package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/Hyper-Solutions/hyper-sdk-go/v2"
	"github.com/Hyper-Solutions/hyper-sdk-go/v2/datadome"
	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/cookiejar"
	tls_client "github.com/bogdanfinn/tls-client"
)

const (
	datadomeDDK     = "5B45875B653A484CC79E57036CE9FC" // pokemoncenter.com sitekey
	datadomeTagsURL = "https://dd.pokemoncenter.com/js/"
)

type DataDomeTagsResponse struct {
	Status int    `json:"status"`
	Cookie string `json:"cookie"`
}

type Logger interface {
	Log(format string, args ...any)
}

type DataDomeInterstitialResponse struct {
	Cookie string `json:"cookie"`
	View   string `json:"view"`
	URL    string `json:"url"`
}

func IsDataDomeInterstitial(statusCode int, body string) bool {
	return statusCode == 403 && strings.Contains(body, "ct.captcha-delivery.com/i.js")
}

// IsDataDomeFingerprintBlock detects blocks with 't':'fe' (fingerprint enforcement).
func IsDataDomeFingerprintBlock(statusCode int, body string) bool {
	return statusCode == 403 && strings.Contains(body, "var dd=") && strings.Contains(body, "'t':'fe'")
}

func SolveDataDomeInterstitial(ctx context.Context, client tls_client.HttpClient, session *hyper.Session, pageURL string, challengeBody string, logger Logger) (*hyper.Headers, error) {
	parsedURL, err := url.Parse(pageURL)
	if err != nil {
		return nil, err
	}

	datadomeCookie := getDatadomeCookie(client, parsedURL)
	if datadomeCookie == "" {
		return nil, fmt.Errorf("no datadome cookie found in challenge response")
	}

	logger.Log("Parsing interstitial device check link...")
	deviceLink, err := datadome.ParseInterstitialDeviceCheckLink(
		strings.NewReader(challengeBody),
		datadomeCookie,
		pageURL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse device check link: %w", err)
	}

	logger.Log("Fetching interstitial script...")
	deviceHTML, err := fetchDeviceCheckPage(client, deviceLink, pageURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch device check page: %w", err)
	}

	externalIP, err := getExternalIP(client, session.ApiKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get external IP: %w", err)
	}

	logger.Log("Generating interstitial payload...")
	limiter := GetHyperLimiter(3)
	limiter.Acquire()
	defer limiter.Release()

	payload, headers, err := session.GenerateDataDomeInterstitial(ctx, &hyper.DataDomeInterstitialInput{
		UserAgent:      Chrome143UserAgent,
		DeviceLink:     deviceLink,
		Html:           deviceHTML,
		AcceptLanguage: "en-US",
		IP:             externalIP,
	})
	if err != nil {
		if ContainsFatalErrorString(err) {
			return nil, NewFatalError(fmt.Errorf("failed to generate interstitial payload: %w", err))
		}
		return nil, fmt.Errorf("failed to generate interstitial payload: %w", err)
	}

	logger.Log("Submitting interstitial solution...")
	resp, err := submitInterstitialPayload(client, deviceLink, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to submit interstitial payload: %w", err)
	}

	if resp.Cookie != "" {
		newCookieValue := extractCookieValue(resp.Cookie)
		setDatadomeCookie(client, parsedURL, newCookieValue)
		logger.Log("DataDome cookie updated successfully")
	}

	return headers, nil
}

func fetchDeviceCheckPage(client tls_client.HttpClient, deviceLink, referer string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, deviceLink, nil)
	if err != nil {
		return "", err
	}

	req.Header = http.Header{
		"sec-ch-ua-platform": {`"Windows"`},
		"user-agent":         {Chrome143UserAgent},
		"sec-ch-ua":          {Chrome143SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"accept":             {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"sec-fetch-site":     {"cross-site"},
		"sec-fetch-mode":     {"navigate"},
		"sec-fetch-dest":     {"document"},
		"referer":            {referer},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {"en-US,en;q=0.9"},
		http.HeaderOrderKey: {
			"sec-ch-ua-platform",
			"user-agent",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-dest",
			"referer",
			"accept-encoding",
			"accept-language",
		},
		http.PHeaderOrderKey: PseudoHeaderOrder,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := readResponseBody(resp)
	if err != nil {
		return "", err
	}

	return string(bodyBytes), nil
}

func submitInterstitialPayload(client tls_client.HttpClient, deviceLink, payload string) (*DataDomeInterstitialResponse, error) {
	req, err := http.NewRequest(http.MethodPost, "https://geo.captcha-delivery.com/interstitial/", strings.NewReader(payload))
	if err != nil {
		return nil, err
	}

	req.Header = http.Header{
		"sec-ch-ua-platform": {`"Windows"`},
		"user-agent":         {Chrome143UserAgent},
		"sec-ch-ua":          {Chrome143SecChUa},
		"content-type":       {"application/x-www-form-urlencoded; charset=UTF-8"},
		"sec-ch-ua-mobile":   {"?0"},
		"accept":             {"*/*"},
		"origin":             {"https://geo.captcha-delivery.com"},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-dest":     {"empty"},
		"referer":            {deviceLink},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {"en-US,en;q=0.9"},
		http.HeaderOrderKey: {
			"content-length",
			"sec-ch-ua-platform",
			"user-agent",
			"sec-ch-ua",
			"content-type",
			"sec-ch-ua-mobile",
			"accept",
			"origin",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-dest",
			"referer",
			"accept-encoding",
			"accept-language",
		},
		http.PHeaderOrderKey: PseudoHeaderOrder,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result DataDomeInterstitialResponse
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w (body: %s)", err, string(bodyBytes))
	}

	return &result, nil
}

func submitDataDomeTags(ctx context.Context, client tls_client.HttpClient, session *hyper.Session, pageURL, datadomeCookie, externalIP, tagsType string) (string, error) {
	limiter := GetHyperLimiter(3)
	limiter.Acquire()
	defer limiter.Release()

	payload, err := session.GenerateDataDomeTags(ctx, &hyper.DataDomeTagsInput{
		UserAgent:      Chrome143UserAgent,
		Cid:            datadomeCookie,
		Ddk:            datadomeDDK,
		Referer:        pageURL,
		Type:           tagsType,
		Version:        "4.18.0",
		AcceptLanguage: "en-US",
		IP:             externalIP,
	})
	if err != nil {
		if ContainsFatalErrorString(err) {
			return "", NewFatalError(err)
		}
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, datadomeTagsURL, strings.NewReader(payload))
	if err != nil {
		return "", err
	}

	req.Header = http.Header{
		"content-type":       {"application/x-www-form-urlencoded"},
		"sec-ch-ua-platform": {`"Windows"`},
		"user-agent":         {Chrome143UserAgent},
		"sec-ch-ua":          {Chrome143SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"accept":             {"*/*"},
		"origin":             {"https://www.pokemoncenter.com"},
		"sec-fetch-site":     {"same-site"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-dest":     {"empty"},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {"en-US,en;q=0.9"},
		"priority":           {"u=1, i"},
		http.HeaderOrderKey: {
			"content-length",
			"sec-ch-ua-platform",
			"user-agent",
			"sec-ch-ua",
			"content-type",
			"sec-ch-ua-mobile",
			"accept",
			"origin",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-dest",
			"accept-encoding",
			"accept-language",
			"priority",
		},
		http.PHeaderOrderKey: PseudoHeaderOrder,
	}

	// Use empty cookie jar to avoid sending existing cookies
	tempJar, _ := cookiejar.New(nil)
	currentJar := client.GetCookieJar()
	client.SetCookieJar(tempJar)

	resp, err := client.Do(req)
	if err != nil {
		client.SetCookieJar(currentJar)
		return "", err
	}
	defer resp.Body.Close()
	client.SetCookieJar(currentJar)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var tagsResp DataDomeTagsResponse
	if err := json.Unmarshal(body, &tagsResp); err != nil {
		return "", fmt.Errorf("failed to unmarshal tags response: %w (body: %s)", err, string(body))
	}

	if tagsResp.Cookie != "" {
		return extractCookieValue(tagsResp.Cookie), nil
	}

	return "", nil
}

func getDatadomeCookie(client tls_client.HttpClient, u *url.URL) string {
	cookies := client.GetCookies(u)
	for _, c := range cookies {
		if c.Name == "datadome" {
			return c.Value
		}
	}
	return ""
}

func setDatadomeCookie(client tls_client.HttpClient, u *url.URL, value string) {
	cookie := &http.Cookie{
		Name:   "datadome",
		Value:  value,
		Domain: ".pokemoncenter.com",
		Path:   "/",
	}
	client.SetCookies(u, []*http.Cookie{cookie})
}

func setDatadomeCookieForHost(client tls_client.HttpClient, hostURL, value string) {
	u, _ := url.Parse(hostURL)
	setDatadomeCookie(client, u, value)
}

// extractCookieValue parses "name=value; ..." -> "value"
func extractCookieValue(setCookie string) string {
	idx := strings.Index(setCookie, ";")
	if idx == -1 {
		idx = len(setCookie)
	}
	nameValue := setCookie[:idx]
	parts := strings.SplitN(nameValue, "=", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}
