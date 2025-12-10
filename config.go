package main

import "os"

var (
	hyperAPIKey   string
	captchaAPIKey string
	capmonsterKey string
	capsolverKey  string
)

func getAPIKey(buildKey, envKey string) string {
	if buildKey != "" {
		return buildKey
	}
	return os.Getenv(envKey)
}

func GetHyperAPIKey() string      { return getAPIKey(hyperAPIKey, "HYPER_API_KEY") }
func GetCaptchaAPIKey() string    { return getAPIKey(captchaAPIKey, "2CAP_KEY") }
func GetCapMonsterAPIKey() string { return getAPIKey(capmonsterKey, "CAPMONSTER_KEY") }
func GetCapSolverAPIKey() string  { return getAPIKey(capsolverKey, "CAPSOLVER_KEY") }
