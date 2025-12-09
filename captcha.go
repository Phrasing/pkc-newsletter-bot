package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

// =============================================================================
// CapSolver API
// =============================================================================

type CapSolverResponse struct {
	ErrorId          int32          `json:"errorId"`
	ErrorCode        string         `json:"errorCode"`
	ErrorDescription string         `json:"errorDescription"`
	TaskId           string         `json:"taskId"`
	Status           string         `json:"status"`
	Solution         map[string]any `json:"solution"`
}

func CapSolver(ctx context.Context, apiKey string, taskData map[string]any) (*CapSolverResponse, error) {
	res, err := capSolverCreateTask(ctx, apiKey, taskData)
	if err != nil {
		return nil, err
	}
	if res.ErrorId == 1 {
		return nil, handleCapSolverError(res.ErrorCode, res.ErrorDescription)
	}

	return capSolverPollResult(ctx, apiKey, res.TaskId)
}

func capSolverCreateTask(ctx context.Context, apiKey string, taskData map[string]any) (*CapSolverResponse, error) {
	return CapSolverRequest(ctx, "https://api.capsolver.com/createTask", map[string]any{
		"clientKey": apiKey,
		"task":      taskData,
	})
}

func capSolverPollResult(ctx context.Context, apiKey, taskId string) (*CapSolverResponse, error) {
	uri := "https://api.capsolver.com/getTaskResult"
	for {
		select {
		case <-ctx.Done():
			return nil, errors.New("solve timeout")
		case <-time.After(time.Second):
		}

		res, err := CapSolverRequest(ctx, uri, map[string]any{
			"clientKey": apiKey,
			"taskId":    taskId,
		})
		if err != nil {
			return nil, err
		}
		if res.ErrorId == 1 {
			return nil, handleCapSolverError(res.ErrorCode, res.ErrorDescription)
		}
		if res.Status == "ready" {
			return res, nil
		}
	}
}

func handleCapSolverError(code, description string) error {
	err := errors.New(description)
	if isFatalCaptchaError(code) {
		return NewFatalError(err)
	}
	return err
}

func CapSolverRequest(ctx context.Context, uri string, payload any) (*CapSolverResponse, error) {
	return doJSONRequest[CapSolverResponse](ctx, uri, payload, 3)
}

func GetRecapV3Solution(apikey, weburl, webkey, action, userAgent string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	res, err := CapSolver(ctx, apikey, map[string]any{
		"type":       "ReCaptchaV3TaskProxyLess",
		"websiteURL": weburl,
		"websiteKey": webkey,
		"pageAction": action,
		"userAgent":  userAgent,
		"minScore":   0.9,
	})
	if err != nil {
		return "", fmt.Errorf("request error: %v", err)
	}

	return extractRecaptchaToken(res.Solution, res.ErrorId, res.ErrorCode, res.ErrorDescription)
}

func GetRecapV3M1Solution(apikey, weburl, webkey, action, userAgent string, minScore float64) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	res, err := CapSolver(ctx, apikey, map[string]any{
		"type":       "ReCaptchaV3M1TaskProxyLess",
		"websiteURL": weburl,
		"websiteKey": webkey,
		"pageAction": action,
		"minScore":   minScore,
		"userAgent":  userAgent,
	})
	if err != nil {
		return "", fmt.Errorf("request error: %v", err)
	}

	return extractRecaptchaToken(res.Solution, res.ErrorId, res.ErrorCode, res.ErrorDescription)
}

func GetRecapV3SolutionWithProxy(apikey, weburl, webkey, action, proxy, userAgent, anchor, reload string, minScore float64) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	taskData := map[string]any{
		"type":       "ReCaptchaV3Task",
		"websiteURL": weburl,
		"websiteKey": webkey,
		"pageAction": action,
		"proxy":      proxy,
		"userAgent":  userAgent,
		"minScore":   minScore,
	}
	if anchor != "" {
		taskData["anchor"] = anchor
	}
	if reload != "" {
		taskData["reload"] = reload
	}

	res, err := CapSolver(ctx, apikey, taskData)
	if err != nil {
		return "", fmt.Errorf("request error: %v", err)
	}

	return extractRecaptchaToken(res.Solution, res.ErrorId, res.ErrorCode, res.ErrorDescription)
}

// =============================================================================
// 2Captcha API
// =============================================================================

type TwoCaptchaResponse struct {
	ErrorId          int            `json:"errorId"`
	ErrorCode        string         `json:"errorCode"`
	ErrorDescription string         `json:"errorDescription"`
	TaskId           int64          `json:"taskId"`
	Status           string         `json:"status"`
	Solution         map[string]any `json:"solution"`
}

func TwoCaptcha(ctx context.Context, apiKey string, taskData map[string]any) (*TwoCaptchaResponse, error) {
	res, err := twoCaptchaCreateTask(ctx, apiKey, taskData)
	if err != nil {
		return nil, err
	}
	if res.ErrorId != 0 {
		return nil, handleTwoCaptchaError(res.ErrorCode, res.ErrorDescription)
	}

	return twoCaptchaPollResult(ctx, apiKey, res.TaskId)
}

func twoCaptchaCreateTask(ctx context.Context, apiKey string, taskData map[string]any) (*TwoCaptchaResponse, error) {
	return TwoCaptchaRequest(ctx, "https://api.2captcha.com/createTask", map[string]any{
		"clientKey": apiKey,
		"task":      taskData,
	})
}

func twoCaptchaPollResult(ctx context.Context, apiKey string, taskId int64) (*TwoCaptchaResponse, error) {
	uri := "https://api.2captcha.com/getTaskResult"
	for {
		select {
		case <-ctx.Done():
			return nil, errors.New("solve timeout")
		case <-time.After(5 * time.Second): // 2captcha recommends 5s polling
		}

		res, err := TwoCaptchaRequest(ctx, uri, map[string]any{
			"clientKey": apiKey,
			"taskId":    taskId,
		})
		if err != nil {
			return nil, err
		}
		if res.ErrorId != 0 {
			return nil, handleTwoCaptchaError(res.ErrorCode, res.ErrorDescription)
		}
		if res.Status == "ready" {
			return res, nil
		}
	}
}

func handleTwoCaptchaError(code, description string) error {
	err := fmt.Errorf("2captcha error: %s - %s", code, description)
	if isFatalCaptchaError(code) {
		return NewFatalError(err)
	}
	return err
}

func TwoCaptchaRequest(ctx context.Context, uri string, payload any) (*TwoCaptchaResponse, error) {
	return doJSONRequest[TwoCaptchaResponse](ctx, uri, payload, 3)
}

func Get2CaptchaRecapV3Solution(apikey, weburl, webkey, action string, minScore float64) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	taskData := map[string]any{
		"type":       "RecaptchaV3TaskProxyless",
		"websiteURL": weburl,
		"websiteKey": webkey,
		"minScore":   minScore,
	}
	if action != "" {
		taskData["pageAction"] = action
	}

	res, err := TwoCaptcha(ctx, apikey, taskData)
	if err != nil {
		return "", fmt.Errorf("2captcha request error: %v", err)
	}

	token, ok := res.Solution["gRecaptchaResponse"].(string)
	if !ok {
		token, ok = res.Solution["token"].(string)
		if !ok {
			return "", fmt.Errorf("2captcha solver error: no token in response")
		}
	}
	return token, nil
}

// Get2CaptchaRecapV3SolutionWithProxy solves reCAPTCHA v3 using 2Captcha API v1 with a proxy.
// proxyRaw should be in format: host:port:user:pass
func Get2CaptchaRecapV3SolutionWithProxy(apikey, weburl, webkey, action, proxyRaw string, minScore float64) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	proxyFormatted, err := formatProxyFor2Captcha(proxyRaw)
	if err != nil {
		return "", err
	}

	captchaID, err := submit2CaptchaV1Task(ctx, apikey, weburl, webkey, action, proxyFormatted, minScore)
	if err != nil {
		return "", err
	}

	return poll2CaptchaV1Result(ctx, apikey, captchaID)
}

func formatProxyFor2Captcha(proxyRaw string) (string, error) {
	parts := strings.Split(proxyRaw, ":")
	if len(parts) != 4 {
		return "", fmt.Errorf("invalid proxy format, expected host:port:user:pass")
	}
	return fmt.Sprintf("%s:%s@%s:%s", parts[2], parts[3], parts[0], parts[1]), nil
}

func submit2CaptchaV1Task(ctx context.Context, apikey, weburl, webkey, action, proxy string, minScore float64) (string, error) {
	submitURL := fmt.Sprintf(
		"https://2captcha.com/in.php?key=%s&method=userrecaptcha&version=v3&googlekey=%s&pageurl=%s&action=%s&min_score=%.1f&proxy=%s&proxytype=HTTP&json=1",
		apikey, webkey, weburl, action, minScore, proxy,
	)

	body, err := doHTTPGet(ctx, submitURL)
	if err != nil {
		return "", fmt.Errorf("submit request failed: %w", err)
	}

	var resp struct {
		Status  int    `json:"status"`
		Request string `json:"request"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("failed to parse submit response: %s", string(body))
	}
	if resp.Status != 1 {
		err := fmt.Errorf("2captcha submit error: %s", resp.Request)
		if isFatalCaptchaError(resp.Request) {
			return "", NewFatalError(err)
		}
		return "", err
	}

	return resp.Request, nil
}

func poll2CaptchaV1Result(ctx context.Context, apikey, captchaID string) (string, error) {
	resultURL := fmt.Sprintf("https://2captcha.com/res.php?key=%s&action=get&id=%s&json=1", apikey, captchaID)

	for {
		select {
		case <-ctx.Done():
			return "", errors.New("solve timeout")
		case <-time.After(5 * time.Second):
		}

		body, err := doHTTPGet(ctx, resultURL)
		if err != nil {
			continue // Retry on network error
		}

		var resp struct {
			Status  int    `json:"status"`
			Request string `json:"request"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", fmt.Errorf("failed to parse result response: %s", string(body))
		}

		if resp.Status == 1 {
			return resp.Request, nil
		}
		if resp.Request != "CAPCHA_NOT_READY" {
			err := fmt.Errorf("2captcha error: %s", resp.Request)
			if isFatalCaptchaError(resp.Request) {
				return "", NewFatalError(err)
			}
			return "", err
		}
	}
}

// =============================================================================
// Helpers
// =============================================================================

var fatalCaptchaCodes = []string{
	"ERROR_ZERO_BALANCE",
	"ERROR_KEY_DOES_NOT_EXIST",
	"ERROR_WRONG_USER_KEY",
	"ERROR_WRONG_GOOGLEKEY",
	"ERROR_IP_NOT_ALLOWED",
	"ERROR_IP_BANNED",
}

func isFatalCaptchaError(errorCode string) bool {
	return slices.Contains(fatalCaptchaCodes, errorCode)
}

func extractRecaptchaToken(solution map[string]any, errorId int32, errorCode, errorDesc string) (string, error) {
	token, ok := solution["gRecaptchaResponse"].(string)
	if !ok {
		return "", fmt.Errorf("solver error %d: %s - %s", errorId, errorCode, errorDesc)
	}
	return token, nil
}

func doJSONRequest[T any](ctx context.Context, uri string, payload any, maxRetries int) (*T, error) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 30 * time.Second}
	var lastErr error

	for attempt := range maxRetries {
		if attempt > 0 {
			backoff := time.Duration(1<<attempt) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		req, err := http.NewRequestWithContext(ctx, "POST", uri, bytes.NewReader(payloadBytes))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		responseData, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		result := new(T)
		if err := json.Unmarshal(responseData, result); err != nil {
			return nil, err
		}
		return result, nil
	}

	return nil, fmt.Errorf("API request failed after %d retries: %w", maxRetries, lastErr)
}

func doHTTPGet(ctx context.Context, url string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}
