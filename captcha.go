package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

var byteBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 4*1024)
		return &b
	},
}

func getBuffer() *[]byte {
	return byteBufferPool.Get().(*[]byte)
}

func putBuffer(b *[]byte) {
	*b = (*b)[:0]
	byteBufferPool.Put(b)
}

var errSolveTimeout = errors.New("solve timeout")

type CaptchaProvider struct {
	Name   string
	APIKey string
	Solve  func(apikey, weburl, webkey, action, proxy, userAgent string, minScore float64) (string, error)
}

type CaptchaProviderManager struct {
	providers []*CaptchaProvider
	mu        sync.Mutex
	index     int
}

func NewCaptchaProviderManager() *CaptchaProviderManager {
	manager := &CaptchaProviderManager{
		providers: make([]*CaptchaProvider, 0, 3),
	}

	if pkcUseCapmonster {
		if key := GetCapMonsterAPIKey(); key != "" {
			manager.providers = append(manager.providers, &CaptchaProvider{
				Name:   "CapMonster",
				APIKey: key,
				Solve:  GetCapMonsterRecapV3Solution,
			})
		}
	}
	if pkcUseTwoCaptcha {
		if key := GetCaptchaAPIKey(); key != "" {
			manager.providers = append(manager.providers, &CaptchaProvider{
				Name:   "2Captcha",
				APIKey: key,
				Solve:  Get2CaptchaRecapV3Solution,
			})
		}
	}
	if pkcUseCapsolver {
		if key := GetCapSolverAPIKey(); key != "" {
			manager.providers = append(manager.providers, &CaptchaProvider{
				Name:   "CapSolver",
				APIKey: key,
				Solve:  GetCapSolverRecapV3Solution,
			})
		}
	}

	return manager
}

func (m *CaptchaProviderManager) Next() *CaptchaProvider {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.providers) == 0 {
		return nil
	}

	provider := m.providers[m.index]
	m.index = (m.index + 1) % len(m.providers)
	return provider
}

func (m *CaptchaProviderManager) Count() int {
	return len(m.providers)
}

func (m *CaptchaProviderManager) Providers() []string {
	names := make([]string, len(m.providers))
	for i, p := range m.providers {
		names[i] = p.Name
	}
	return names
}

type capSolverPollRequest struct {
	ClientKey string `json:"clientKey"`
	TaskId    string `json:"taskId"`
}

type twoCaptchaPollRequest struct {
	ClientKey string `json:"clientKey"`
	TaskId    int64  `json:"taskId"`
}

type twoCaptchaV1Response struct {
	Status  int    `json:"status"`
	Request string `json:"request"`
}

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
		return nil, wrapCaptchaError("capsolver", res.ErrorCode, res.ErrorDescription)
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
	req := capSolverPollRequest{ClientKey: apiKey, TaskId: taskId}
	for {
		select {
		case <-ctx.Done():
			return nil, errSolveTimeout
		case <-time.After(time.Second):
		}

		res, err := CapSolverRequest(ctx, "https://api.capsolver.com/getTaskResult", req)
		if err != nil {
			return nil, err
		}
		if res.ErrorId == 1 {
			return nil, wrapCaptchaError("capsolver", res.ErrorCode, res.ErrorDescription)
		}
		if res.Status == "ready" {
			return res, nil
		}
	}
}

func CapSolverRequest(ctx context.Context, uri string, payload any) (*CapSolverResponse, error) {
	return doJSONRequest[CapSolverResponse](ctx, uri, payload, 3)
}

func GetCapSolverRecapV3Solution(apikey, weburl, webkey, action, proxy, userAgent string, minScore float64) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	taskData := map[string]any{
		"type":       "ReCaptchaV3Task",
		"websiteURL": weburl,
		"websiteKey": webkey,
		"minScore":   minScore,
		"proxy":      proxy,
		"userAgent":  userAgent,
	}
	if action != "" {
		taskData["pageAction"] = action
	}

	res, err := CapSolver(ctx, apikey, taskData)
	if err != nil {
		return "", fmt.Errorf("capsolver request error: %v", err)
	}

	return extractToken(res.Solution, "capsolver")
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

	return extractToken(res.Solution, "capsolver")
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

	return extractToken(res.Solution, "capsolver")
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

	return extractToken(res.Solution, "capsolver")
}

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
		return nil, wrapCaptchaError("2captcha", res.ErrorCode, res.ErrorDescription)
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
	req := twoCaptchaPollRequest{ClientKey: apiKey, TaskId: taskId}
	for {
		select {
		case <-ctx.Done():
			return nil, errSolveTimeout
		case <-time.After(5 * time.Second):
		}

		res, err := TwoCaptchaRequest(ctx, "https://api.2captcha.com/getTaskResult", req)
		if err != nil {
			return nil, err
		}
		if res.ErrorId != 0 {
			return nil, wrapCaptchaError("2captcha", res.ErrorCode, res.ErrorDescription)
		}
		if res.Status == "ready" {
			return res, nil
		}
	}
}

func TwoCaptchaRequest(ctx context.Context, uri string, payload any) (*TwoCaptchaResponse, error) {
	return doJSONRequest[TwoCaptchaResponse](ctx, uri, payload, 3)
}

func Get2CaptchaRecapV3Solution(apikey, weburl, webkey, action, proxy, userAgent string, minScore float64) (string, error) {
	return Get2CaptchaRecapV3SolutionWithProxy(apikey, weburl, webkey, action, proxy, minScore)
}

func Get2CaptchaRecapV3SolutionWithProxy(apikey, weburl, webkey, action, proxyRaw string, minScore float64) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	proxyFormatted, err := formatProxyFor2Captcha(proxyRaw)
	if err != nil {
		return "", err
	}

	captchaID, err := submit2CaptchaV1Task(apikey, weburl, webkey, action, proxyFormatted, minScore)
	if err != nil {
		return "", err
	}

	return poll2CaptchaV1Result(ctx, apikey, captchaID)
}

func formatProxyFor2Captcha(proxyRaw string) (string, error) {
	proxyRaw = strings.TrimPrefix(strings.TrimPrefix(proxyRaw, "http://"), "https://")

	if strings.Contains(proxyRaw, "@") {
		return proxyRaw, nil
	}

	parts := strings.Split(proxyRaw, ":")
	if len(parts) == 4 {
		return fmt.Sprintf("%s:%s@%s:%s", parts[2], parts[3], parts[0], parts[1]), nil
	}
	if len(parts) == 2 {
		return proxyRaw, nil
	}

	return "", fmt.Errorf("invalid proxy format: %s", proxyRaw)
}

func submit2CaptchaV1Task(apikey, weburl, webkey, action, proxy string, minScore float64) (string, error) {
	submitURL := fmt.Sprintf(
		"https://2captcha.com/in.php?key=%s&method=userrecaptcha&version=v3&googlekey=%s&pageurl=%s&action=%s&min_score=%.1f&proxy=%s&proxytype=HTTP&json=1",
		apikey, webkey, weburl, action, minScore, proxy,
	)

	body, err := doHTTPGet(submitURL)
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
		return "", wrapCaptchaError("2captcha", resp.Request, "")
	}

	return resp.Request, nil
}

func poll2CaptchaV1Result(ctx context.Context, apikey, captchaID string) (string, error) {
	resultURL := fmt.Sprintf("https://2captcha.com/res.php?key=%s&action=get&id=%s&json=1", apikey, captchaID)
	var resp twoCaptchaV1Response

	for {
		select {
		case <-ctx.Done():
			return "", errSolveTimeout
		case <-time.After(5 * time.Second):
		}

		body, err := doHTTPGet(resultURL)
		if err != nil {
			continue
		}

		if err := json.Unmarshal(body, &resp); err != nil {
			return "", fmt.Errorf("failed to parse result response: %s", string(body))
		}

		if resp.Status == 1 {
			return resp.Request, nil
		}
		if resp.Request != "CAPCHA_NOT_READY" {
			return "", wrapCaptchaError("2captcha", resp.Request, "")
		}
	}
}

type CapMonsterResponse struct {
	ErrorId          int            `json:"errorId"`
	ErrorCode        string         `json:"errorCode"`
	ErrorDescription string         `json:"errorDescription"`
	TaskId           int            `json:"taskId"`
	Status           string         `json:"status"`
	Solution         map[string]any `json:"solution"`
}

func CapMonster(ctx context.Context, apiKey string, taskData map[string]any) (*CapMonsterResponse, error) {
	res, err := capMonsterCreateTask(ctx, apiKey, taskData)
	if err != nil {
		return nil, err
	}
	if res.ErrorId != 0 {
		return nil, wrapCaptchaError("capmonster", res.ErrorCode, res.ErrorDescription)
	}
	return capMonsterPollResult(ctx, apiKey, res.TaskId)
}

func capMonsterCreateTask(ctx context.Context, apiKey string, taskData map[string]any) (*CapMonsterResponse, error) {
	return CapMonsterRequest(ctx, "https://api.capmonster.cloud/createTask", map[string]any{
		"clientKey": apiKey,
		"task":      taskData,
	})
}

func capMonsterPollResult(ctx context.Context, apiKey string, taskId int) (*CapMonsterResponse, error) {
	req := struct {
		ClientKey string `json:"clientKey"`
		TaskId    int    `json:"taskId"`
	}{
		ClientKey: apiKey,
		TaskId:    taskId,
	}
	for {
		select {
		case <-ctx.Done():
			return nil, errSolveTimeout
		case <-time.After(2 * time.Second):
		}

		res, err := CapMonsterRequest(ctx, "https://api.capmonster.cloud/getTaskResult", req)
		if err != nil {
			return nil, err
		}
		if res.ErrorId != 0 {
			return nil, wrapCaptchaError("capmonster", res.ErrorCode, res.ErrorDescription)
		}
		if res.Status == "ready" {
			return res, nil
		}
	}
}

func CapMonsterRequest(ctx context.Context, uri string, payload any) (*CapMonsterResponse, error) {
	return doJSONRequest[CapMonsterResponse](ctx, uri, payload, 3)
}

func GetCapMonsterRecapV3Solution(apikey, weburl, webkey, action, proxy, userAgent string, minScore float64) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
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

	res, err := CapMonster(ctx, apikey, taskData)
	if err != nil {
		return "", fmt.Errorf("capmonster request error: %v", err)
	}

	return extractToken(res.Solution, "capmonster")
}

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

func wrapCaptchaError(provider, code, description string) error {
	var err error
	if description != "" {
		err = fmt.Errorf("%s error: %s - %s", provider, code, description)
	} else {
		err = fmt.Errorf("%s error: %s", provider, code)
	}
	if isFatalCaptchaError(code) {
		return NewFatalError(err)
	}
	return err
}

func extractToken(solution map[string]any, provider string) (string, error) {
	if token, ok := solution["gRecaptchaResponse"].(string); ok {
		return token, nil
	}
	if token, ok := solution["token"].(string); ok {
		return token, nil
	}
	return "", fmt.Errorf("%s: no token in solution", provider)
}

var fastClient = &fasthttp.Client{
	ReadTimeout:  30 * time.Second,
	WriteTimeout: 30 * time.Second,
}

func doJSONRequest[T any](ctx context.Context, uri string, payload any, maxRetries int) (*T, error) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

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

		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()

		req.SetRequestURI(uri)
		req.Header.SetMethod(fasthttp.MethodPost)
		req.Header.SetContentType("application/json")
		req.SetBody(payloadBytes)

		err := fastClient.Do(req, resp)

		buf := getBuffer()
		*buf = append(*buf, resp.Body()...)

		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)

		if err != nil {
			putBuffer(buf)
			lastErr = err
			continue
		}

		result := new(T)
		if unmarshalErr := json.Unmarshal(*buf, result); unmarshalErr != nil {
			putBuffer(buf)
			return nil, unmarshalErr
		}
		putBuffer(buf)
		return result, nil
	}

	return nil, fmt.Errorf("API request failed after %d retries: %w", maxRetries, lastErr)
}

func doHTTPGet(url string) ([]byte, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(url)
	req.Header.SetMethod(fasthttp.MethodGet)

	if err := fastClient.Do(req, resp); err != nil {
		return nil, err
	}

	return append([]byte(nil), resp.Body()...), nil
}
