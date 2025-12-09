package main

import "os"

// Build-time variables - inject via ldflags
// Example: go build -ldflags "-X main.hyperAPIKey=YOUR_KEY -X main.captchaAPIKey=YOUR_KEY"
var (
	hyperAPIKey   string // -X main.hyperAPIKey=...
	captchaAPIKey string // -X main.captchaAPIKey=...
)

// GetHyperAPIKey returns the Hyper API key (build-time or env fallback)
func GetHyperAPIKey() string {
	if hyperAPIKey != "" {
		return hyperAPIKey
	}
	return os.Getenv("HYPER_API_KEY")
}

// GetCaptchaAPIKey returns the 2Captcha API key (build-time or env fallback)
func GetCaptchaAPIKey() string {
	if captchaAPIKey != "" {
		return captchaAPIKey
	}
	return os.Getenv("2CAP_KEY")
}
