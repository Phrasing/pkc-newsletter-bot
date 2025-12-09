package main

import (
	"github.com/bogdanfinn/fhttp/http2"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

const (
	Chrome137UserAgent       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"
	Chrome137SecChUa         = `"Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"`
	Chrome137FullVersionList = `"Google Chrome";v="137.0.7151.55", "Chromium";v="137.0.7151.55", "Not/A)Brand";v="24.0.0.0"`
)

// Chrome137BrowserProfile is the browser profile for Chrome 137.
var Chrome137BrowserProfile = &BrowserProfile{
	UserAgent:       Chrome137UserAgent,
	SecChUa:         Chrome137SecChUa,
	FullVersionList: Chrome137FullVersionList,
	Platform:        `"Windows"`,
	Mobile:          "?0",
}

// Fake signature schemes not defined in utls.
const (
	FakePKCS1WithSHA224  tls.SignatureScheme = 0x0301
	FakeECDSAWithSHA224  tls.SignatureScheme = 0x0303
	FakeDSAWithSHA256    tls.SignatureScheme = 0x0402
	FakeDSAWithSHA1      tls.SignatureScheme = 0x0302
	FakeSHA1WithDSA      tls.SignatureScheme = 0x0202
	FakeEd448            tls.SignatureScheme = 0x0808
	FakePSSWithSHA256PSS tls.SignatureScheme = 0x0809
	FakePSSWithSHA384PSS tls.SignatureScheme = 0x080a
	FakePSSWithSHA512PSS tls.SignatureScheme = 0x080b
)

// Fake curve IDs for ffdhe groups and X448.
const (
	FakeFFDHE2048 tls.CurveID = 256
	FakeFFDHE3072 tls.CurveID = 257
	FakeFFDHE4096 tls.CurveID = 258
	FakeFFDHE6144 tls.CurveID = 259
	FakeFFDHE8192 tls.CurveID = 260
	FakeX448      tls.CurveID = 30
)

func GetChrome137Spec() (tls.ClientHelloSpec, error) {
	return tls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{
			tls.CompressionNone,
		},
		// Extension order from JA3: 0-5-10-11-16-17-23-35-13-43-45-50-51-65281-41
		Extensions: []tls.TLSExtension{
			// 0 - server_name (SNI)
			&tls.SNIExtension{},
			// 5 - status_request (OCSP stapling)
			&tls.StatusRequestExtension{},
			// 10 - supported_groups (elliptic curves)
			&tls.SupportedCurvesExtension{
				Curves: []tls.CurveID{
					tls.X25519,    // 29
					tls.CurveP256, // 23
					tls.CurveP384, // 24
					tls.CurveP521, // 25
					FakeX448,      // 30
					FakeFFDHE2048, // 256
					FakeFFDHE3072, // 257
					FakeFFDHE4096, // 258
					FakeFFDHE6144, // 259
					FakeFFDHE8192, // 260
				},
			},
			// 11 - ec_point_formats
			&tls.SupportedPointsExtension{
				SupportedPoints: []byte{
					tls.PointFormatUncompressed,
				},
			},
			// 16 - application_layer_protocol_negotiation (ALPN)
			&tls.ALPNExtension{
				AlpnProtocols: []string{
					"h2",
					"http/1.1",
				},
			},
			// 17 - status_request_v2
			&tls.StatusRequestV2Extension{},
			// 23 - extended_master_secret
			&tls.ExtendedMasterSecretExtension{},
			// 35 - session_ticket
			&tls.SessionTicketExtension{},
			// 13 - signature_algorithms
			&tls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []tls.SignatureScheme{
					tls.ECDSAWithP256AndSHA256, // ecdsa_secp256r1_sha256
					tls.ECDSAWithP384AndSHA384, // ecdsa_secp384r1_sha384
					tls.ECDSAWithP521AndSHA512, // ecdsa_secp521r1_sha512
					tls.Ed25519,                // ed25519
					FakeEd448,                  // ed448
					tls.PSSWithSHA256,          // rsa_pss_rsae_sha256
					tls.PSSWithSHA384,          // rsa_pss_rsae_sha384
					tls.PSSWithSHA512,          // rsa_pss_rsae_sha512
					FakePSSWithSHA256PSS,       // rsa_pss_pss_sha256
					FakePSSWithSHA384PSS,       // rsa_pss_pss_sha384
					FakePSSWithSHA512PSS,       // rsa_pss_pss_sha512
					tls.PKCS1WithSHA256,        // rsa_pkcs1_sha256
					tls.PKCS1WithSHA384,        // rsa_pkcs1_sha384
					tls.PKCS1WithSHA512,        // rsa_pkcs1_sha512
					FakeDSAWithSHA256,          // 0x402
					FakeECDSAWithSHA224,        // 0x303
					FakePKCS1WithSHA224,        // 0x301
					FakeDSAWithSHA1,            // 0x302
					tls.ECDSAWithSHA1,          // ecdsa_sha1
					tls.PKCS1WithSHA1,          // rsa_pkcs1_sha1
					FakeSHA1WithDSA,            // 0x202
				},
			},
			// 43 - supported_versions
			&tls.SupportedVersionsExtension{
				Versions: []uint16{
					tls.VersionTLS13,
					tls.VersionTLS12,
				},
			},
			// 45 - psk_key_exchange_modes
			&tls.PSKKeyExchangeModesExtension{
				Modes: []uint8{
					tls.PskModeDHE,
				},
			},
			// 50 - signature_algorithms_cert
			&tls.SignatureAlgorithmsCertExtension{
				SupportedSignatureAlgorithms: []tls.SignatureScheme{
					tls.ECDSAWithP256AndSHA256, // 0x0403
					tls.ECDSAWithP384AndSHA384, // 0x0503
					tls.ECDSAWithP521AndSHA512, // 0x0603
					tls.Ed25519,                // 0x0807
					FakeEd448,                  // 0x0808
					tls.PSSWithSHA256,          // 0x0804
					tls.PSSWithSHA384,          // 0x0805
					tls.PSSWithSHA512,          // 0x0806
					FakePSSWithSHA256PSS,       // 0x0809
					FakePSSWithSHA384PSS,       // 0x080a
					FakePSSWithSHA512PSS,       // 0x080b
					tls.PKCS1WithSHA256,        // 0x0401
					tls.PKCS1WithSHA384,        // 0x0501
					tls.PKCS1WithSHA512,        // 0x0601
					FakeDSAWithSHA256,          // 0x0402
					FakeECDSAWithSHA224,        // 0x0303
					FakePKCS1WithSHA224,        // 0x0301
					FakeDSAWithSHA1,            // 0x0302
					tls.ECDSAWithSHA1,          // 0x0203
					tls.PKCS1WithSHA1,          // 0x0201
					FakeSHA1WithDSA,            // 0x0202
				},
			},
			// 51 - key_share
			&tls.KeyShareExtension{
				KeyShares: []tls.KeyShare{
					{Group: tls.X25519},
					{Group: tls.CurveP256},
				},
			},
			// 65281 - renegotiation_info
			&tls.RenegotiationInfoExtension{
				Renegotiation: tls.RenegotiateOnceAsClient,
			},
			// 41 - pre_shared_key (PSK) - MUST be last extension per TLS 1.3 spec
			// This extension will appear in the fingerprint when PSK data is provided
			// For session resumption, provide actual Identities and Binders
			&tls.FakePreSharedKeyExtension{
				Identities: []tls.PskIdentity{
					{
						Label:               make([]byte, 113), // Placeholder session ticket
						ObfuscatedTicketAge: 0,
					},
				},
				Binders: [][]byte{
					make([]byte, 32), // Placeholder binder (SHA-256 sized)
				},
			},
		},
	}, nil
}

// PSK extension (41) must always remain last per TLS 1.3 specification.
func GetChrome137ClientHelloID() tls.ClientHelloID {
	return tls.ClientHelloID{
		Client:               "Chrome",
		RandomExtensionOrder: true,
		Version:              "137",
		Seed:                 nil,
		SpecFactory:          GetChrome137Spec,
	}
}

var Chrome137Profile = profiles.NewClientProfile(
	GetChrome137ClientHelloID(),
	map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 6291456,
		http2.SettingMaxHeaderListSize: 262144,
	},
	[]http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	[]string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	15663105,
	nil, // No priority frames for Chrome
	nil, // No header priorities
)

func init() {
	Chrome137BrowserProfile.TLSProfile = Chrome137Profile
}
