package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const probeTimeout = 90 * time.Second

// probeAccountQualityFn is indirected so tests can exercise the probe pipeline
// without reaching the upstream API.
var probeAccountQualityFn = probeAccountQuality

type probeResult struct {
	Key            string  `json:"key"`
	Name           string  `json:"name,omitempty"`
	Email          string  `json:"email,omitempty"`
	Classification string  `json:"classification"`
	TPS            float64 `json:"tps"`
	OutputTokens   int64   `json:"output_tokens"`
	DurationMs     int64   `json:"duration_ms"`
	FirstTokenMs   int64   `json:"first_token_ms"`
	Model          string  `json:"model,omitempty"`
	Error          string  `json:"error,omitempty"`
}

func httpClientThroughProxy(proxyURL string, timeout time.Duration) (*http.Client, error) {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 15 * time.Second,
	}
	if strings.TrimSpace(proxyURL) != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("代理 URL 无效")
		}
		transport.Proxy = http.ProxyURL(u)
	}
	return &http.Client{Timeout: timeout, Transport: transport}, nil
}

func applyGrokClientHeaders(req *http.Request, auth authFile) {
	// Always force Grok CLI headers — missing X-XAI-Token-Auth yields
	// upstream 401 "x_xai_token_auth=none / no auth context".
	req.Header.Set("X-XAI-Token-Auth", "xai-grok-cli")
	req.Header.Set("x-grok-client-version", "0.2.93")
	req.Header.Set("x-grok-client-identifier", "grok-shell")
	req.Header.Set("User-Agent", "CPA-account-guard/1.0")
	if headers, ok := auth.Raw["headers"].(map[string]any); ok {
		for k, v := range headers {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				req.Header.Set(k, s)
			}
		}
	}
	// Re-assert critical headers after the auth map copy (it may hold empties).
	if req.Header.Get("X-XAI-Token-Auth") == "" {
		req.Header.Set("X-XAI-Token-Auth", "xai-grok-cli")
	}
	if req.Header.Get("x-grok-client-version") == "" {
		req.Header.Set("x-grok-client-version", "0.2.93")
	}
	if req.Header.Get("x-grok-client-identifier") == "" {
		req.Header.Set("x-grok-client-identifier", "grok-shell")
	}
}

// probeAccountQuality runs one real streaming completion with this account's
// own credentials, through the account's own proxy_url when it has one.
func probeAccountQuality(pol policyConfig, auth authFile) probeResult {
	res := probeResult{Model: pol.ProbeModel}

	token, _ := auth.Raw["access_token"].(string)
	if strings.TrimSpace(token) == "" {
		res.Classification = "error"
		res.Error = "账号缺少 access_token"
		return res
	}

	client, err := httpClientThroughProxy(auth.ProxyURL, probeTimeout)
	if err != nil {
		res.Classification = "error"
		res.Error = err.Error()
		return res
	}

	maxTok := pol.ProbeMaxTokens
	if maxTok <= 0 {
		maxTok = defaultProbeMaxTokens
	}
	payload, _ := json.Marshal(map[string]any{
		"model": pol.ProbeModel,
		"messages": []map[string]string{
			{"role": "user", "content": "Write a detailed technical explanation of how TCP slow start works, at least 12 sentences, plain text only."},
		},
		"stream":      true,
		"max_tokens":  maxTok,
		"temperature": 0.7,
	})

	baseURL, _ := auth.Raw["base_url"].(string)
	if baseURL == "" {
		baseURL = "https://cli-chat-proxy.grok.com/v1"
	}
	baseURL = strings.TrimRight(baseURL, "/")

	req, err := http.NewRequest(http.MethodPost, baseURL+"/chat/completions", bytes.NewReader(payload))
	if err != nil {
		res.Classification = "error"
		res.Error = "无法创建探测请求"
		return res
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	applyGrokClientHeaders(req, auth)

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		res.Classification = "error"
		res.DurationMs = time.Since(start).Milliseconds()
		res.Error = "探测请求失败: " + truncate(err.Error(), 160)
		return res
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		res.Classification = "error"
		res.DurationMs = time.Since(start).Milliseconds()
		res.Error = fmt.Sprintf("上游 HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
		return res
	}

	var (
		firstTokenAt time.Time
		contentLen   int
		usageOut     int64
		usageReason  int64
	)
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" {
			continue
		}
		if data == "[DONE]" {
			break
		}
		var chunk map[string]any
		if json.Unmarshal([]byte(data), &chunk) != nil {
			continue
		}
		if u, ok := chunk["usage"].(map[string]any); ok {
			usageOut = anyInt(u["completion_tokens"]) + anyInt(u["output_tokens"])
			usageReason = anyInt(u["reasoning_tokens"])
		}
		choices, _ := chunk["choices"].([]any)
		for _, c := range choices {
			cm, _ := c.(map[string]any)
			delta, _ := cm["delta"].(map[string]any)
			if delta == nil {
				continue
			}
			for _, field := range []string{"content", "reasoning_content"} {
				if t, ok := delta[field].(string); ok && t != "" {
					if firstTokenAt.IsZero() {
						firstTokenAt = time.Now()
					}
					contentLen += len([]rune(t))
				}
			}
		}
	}

	res.DurationMs = time.Since(start).Milliseconds()
	if !firstTokenAt.IsZero() {
		res.FirstTokenMs = firstTokenAt.Sub(start).Milliseconds()
	}
	outTokens := usageOut + usageReason
	if outTokens <= 0 {
		outTokens = int64(contentLen / 4)
		if outTokens == 0 && contentLen > 0 {
			outTokens = 1
		}
	}
	if outTokens == 0 {
		res.Classification = "error"
		res.Error = "探测无输出"
		return res
	}
	res.OutputTokens = outTokens
	res.TPS = computeTPS(outTokens, res.DurationMs, res.FirstTokenMs)
	res.Classification = classifyTPS(res.TPS, pol.SoftTPS, pol.HardTPS)
	// Same small-output guard as the passive path.
	if res.Classification == tierHard && outTokens < 32 {
		res.Classification = "healthy"
		res.TPS = 0
	}
	return res
}

// runQualityProbes probes each requested account and feeds every result into
// the guard pipeline, exactly like a passive observation.
func runQualityProbes(store *stateStore, keys []string) ([]probeResult, error) {
	auths, err := listAllAuths()
	if err != nil {
		return nil, err
	}
	byKey := make(map[string]authFile, len(auths))
	for _, a := range auths {
		if key := accountKey(a); key != "" {
			byKey[key] = a
		}
	}

	pol := store.policy()
	out := make([]probeResult, 0, len(keys))
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		auth, ok := byKey[key]
		if !ok {
			out = append(out, probeResult{Key: key, Classification: "error", Error: "账号不存在或已被删除"})
			continue
		}
		res := probeAccountQualityFn(pol, auth)
		res.Key = key
		res.Name = auth.Name
		res.Email = auth.Email

		detail := fmt.Sprintf("主动探测 %s · %d token / %dms", pol.ProbeModel, res.OutputTokens, res.DurationMs)
		if res.Error != "" {
			detail = "主动探测失败: " + res.Error
		}
		// A failed probe counts as a failed call, matching the passive semantics.
		class := res.Classification
		failed := class == "error"
		if failed {
			class = "failed"
		}
		applyObservation(store, auth, observation{
			Classification: class,
			TPS:            res.TPS,
			OutputTokens:   res.OutputTokens,
			DurationMs:     res.DurationMs,
			FirstTokenMs:   res.FirstTokenMs,
			Failed:         failed,
			Source:         sourceProbe,
			Detail:         detail,
		})
		out = append(out, res)
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
