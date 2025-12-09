package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/tls-client/profiles"
)

type testProfile struct {
	Name            string
	Profile         profiles.ClientProfile
	UserAgent       string
	SecChUa         string
	FingerprintFile string
}

var testProfiles = []testProfile{
	{
		Name:            "Chrome143",
		Profile:         chrome143Profile,
		UserAgent:       Chrome143UserAgent,
		SecChUa:         Chrome143SecChUa,
		FingerprintFile: "chrome_143_fingerprint.json",
	},
	{
		Name:            "Chrome137",
		Profile:         Chrome137Profile,
		UserAgent:       Chrome137UserAgent,
		SecChUa:         Chrome137SecChUa,
		FingerprintFile: "chrome_137_fingerprint.json",
	},
}

type fingerprintResponse struct {
	HTTPVersion string `json:"http_version"`
	Method      string `json:"method"`
	UserAgent   string `json:"user_agent"`
	TLS         struct {
		Ciphers              []string `json:"ciphers"`
		JA4                  string   `json:"ja4"`
		PeetprintHash        string   `json:"peetprint_hash"`
		TLSVersionNegotiated string   `json:"tls_version_negotiated"`
	} `json:"tls"`
	HTTP2 struct {
		AkamaiFingerprint     string `json:"akamai_fingerprint"`
		AkamaiFingerprintHash string `json:"akamai_fingerprint_hash"`
	} `json:"http2"`
}

type expectedFingerprint struct {
	TLS struct {
		Ciphers       []string `json:"ciphers"`
		JA4           string   `json:"ja4"`
		PeetprintHash string   `json:"peetprint_hash"`
	} `json:"tls"`
	HTTP2 struct {
		AkamaiFingerprint     string `json:"akamai_fingerprint"`
		AkamaiFingerprintHash string `json:"akamai_fingerprint_hash"`
	} `json:"http2"`
}

func loadExpectedFingerprint(t *testing.T, filename string) expectedFingerprint {
	t.Helper()
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("failed to read fingerprint file %s: %v", filename, err)
	}
	var fp expectedFingerprint
	if err := json.Unmarshal(data, &fp); err != nil {
		t.Fatalf("failed to parse fingerprint file: %v", err)
	}
	return fp
}

func fetchFingerprint(t *testing.T, client interface {
	Do(*http.Request) (*http.Response, error)
}, userAgent, secChUa string) fingerprintResponse {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://tls.peet.ws/api/all", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	req.Header = http.Header{
		"upgrade-insecure-requests": {"1"},
		"user-agent":                {userAgent},
		"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"sec-fetch-site":            {"none"},
		"sec-fetch-mode":            {"navigate"},
		"sec-fetch-user":            {"?1"},
		"sec-fetch-dest":            {"document"},
		"sec-ch-ua":                 {secChUa},
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
		http.PHeaderOrderKey: {
			":method",
			":authority",
			":scheme",
			":path",
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	var fp fingerprintResponse
	if err := json.Unmarshal(body, &fp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	return fp
}

func normalizeCiphers(ciphers []string) []string {
	var result []string
	for _, c := range ciphers {
		if !strings.HasPrefix(c, "TLS_GREASE") {
			result = append(result, c)
		}
	}
	return result
}

func TestClientFingerprint(t *testing.T) {
	for _, tp := range testProfiles {
		t.Run(tp.Name, func(t *testing.T) {
			if _, err := os.Stat(tp.FingerprintFile); os.IsNotExist(err) {
				t.Skipf("fingerprint file %s not found, skipping", tp.FingerprintFile)
			}

			expected := loadExpectedFingerprint(t, tp.FingerprintFile)

			client, err := NewClientWithProfile(nil, "", tp.Profile)
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			// First request establishes session
			_ = fetchFingerprint(t, client, tp.UserAgent, tp.SecChUa)

			// Second request uses PSK for session resumption
			actual := fetchFingerprint(t, client, tp.UserAgent, tp.SecChUa)

			t.Run("HTTP2_Akamai_Fingerprint", func(t *testing.T) {
				if actual.HTTP2.AkamaiFingerprint != expected.HTTP2.AkamaiFingerprint {
					t.Errorf("akamai fingerprint mismatch\ngot:  %s\nwant: %s",
						actual.HTTP2.AkamaiFingerprint, expected.HTTP2.AkamaiFingerprint)
				}
			})

			t.Run("HTTP2_Akamai_Fingerprint_Hash", func(t *testing.T) {
				if actual.HTTP2.AkamaiFingerprintHash != expected.HTTP2.AkamaiFingerprintHash {
					t.Errorf("akamai fingerprint hash mismatch\ngot:  %s\nwant: %s",
						actual.HTTP2.AkamaiFingerprintHash, expected.HTTP2.AkamaiFingerprintHash)
				}
			})

			t.Run("TLS_Ciphers", func(t *testing.T) {
				actualCiphers := normalizeCiphers(actual.TLS.Ciphers)
				expectedCiphers := normalizeCiphers(expected.TLS.Ciphers)

				if len(actualCiphers) != len(expectedCiphers) {
					t.Errorf("cipher count mismatch\ngot:  %d\nwant: %d",
						len(actualCiphers), len(expectedCiphers))
					return
				}

				for i, cipher := range actualCiphers {
					if cipher != expectedCiphers[i] {
						t.Errorf("cipher mismatch at index %d\ngot:  %s\nwant: %s",
							i, cipher, expectedCiphers[i])
					}
				}
			})

			t.Run("TLS_JA4", func(t *testing.T) {
				if actual.TLS.JA4 != expected.TLS.JA4 {
					t.Errorf("JA4 fingerprint mismatch\ngot:  %s\nwant: %s",
						actual.TLS.JA4, expected.TLS.JA4)
				}
			})

			t.Run("TLS_Peetprint_Hash", func(t *testing.T) {
				if actual.TLS.PeetprintHash != expected.TLS.PeetprintHash {
					t.Errorf("peetprint hash mismatch\ngot:  %s\nwant: %s",
						actual.TLS.PeetprintHash, expected.TLS.PeetprintHash)
				}
			})
		})
	}
}
