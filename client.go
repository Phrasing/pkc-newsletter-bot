package main

import (
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

// BrowserProfile bundles a TLS client profile with its corresponding browser headers.
type BrowserProfile struct {
	TLSProfile      profiles.ClientProfile
	UserAgent       string
	SecChUa         string
	FullVersionList string
	Platform        string
	Mobile          string
}

// DefaultProfile is the default browser profile used for new clients.
// Set to Chrome143Profile in tls_chrome143.go.
var DefaultProfile = Chrome143Profile

func NewClient(logger tls_client.Logger, proxyURL string) (tls_client.HttpClient, error) {
	return NewClientWithProfile(logger, proxyURL, DefaultProfile.TLSProfile)
}

func NewClientWithProfile(logger tls_client.Logger, proxyURL string, profile profiles.ClientProfile) (tls_client.HttpClient, error) {
	if logger == nil {
		logger = tls_client.NewNoopLogger()
	}

	jar := tls_client.NewCookieJar()
	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(30),
		tls_client.WithClientProfile(profile),
		tls_client.WithRandomTLSExtensionOrder(),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithCookieJar(jar),
	}

	if proxyURL != "" {
		options = append(options, tls_client.WithProxyUrl(proxyURL))
	}

	return tls_client.NewHttpClient(logger, options...)
}
