package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestComputeTPSUsesGenerationWindow(t *testing.T) {
	// 1050 tokens over 500ms generation window (1100-600) => 2100 TPS
	if got := computeTPS(1050, 1100, 600, 200); got < 2099 || got > 2101 {
		t.Fatalf("computeTPS()=%v, want ~2100", got)
	}
	// tiny generation window falls back to full duration (avoid false hard)
	// 100 tokens / 1000ms => 100 TPS
	if got := computeTPS(100, 1000, 950, 200); got < 99 || got > 101 {
		t.Fatalf("computeTPS()=%v, want ~100 with min window fallback", got)
	}
	if got := computeTPS(100, 0, 0, 200); got != 0 {
		t.Fatalf("computeTPS()=%v, want 0", got)
	}
}

func TestFailureClassificationDoesNotTreatAuthErrorsAsTransport(t *testing.T) {
	for _, test := range []struct {
		status int
		body   string
		kind   string
	}{
		{401, "invalid or expired token", "account_error"},
		{429, "rate limit", "account_error"},
		{0, "dial tcp 10.0.0.1: i/o timeout", "transport_error"},
		{503, "upstream unavailable", "upstream_error"},
	} {
		if got := classifyFailureKind(test.status, test.body); got != test.kind {
			t.Fatalf("classifyFailureKind(%d, %q)=%q, want %q", test.status, test.body, got, test.kind)
		}
	}
}

func TestXAITokenAccountingDoesNotDoubleCountReasoning(t *testing.T) {
	if got := maxInt64(180, 75); got != 180 {
		t.Fatalf("max token total=%d, want 180", got)
	}
	if got := outputTokensFromUsage(map[string]any{
		"completion_tokens": 180,
		"output_tokens":     180,
		"reasoning_tokens":  75,
	}); got != 180 {
		t.Fatalf("authoritative token total=%d, want 180", got)
	}
}

func TestSmallOutputIsIgnoredBeforeTPSThreshold(t *testing.T) {
	pol := defaultPolicy()
	if got := classifyQuality(5000, pol.MinOutputTokens-1, pol); got != "ignored" {
		t.Fatalf("small output classification=%q, want ignored", got)
	}
	if got := classifyQuality(5000, pol.MinOutputTokens, pol); got != "hard" {
		t.Fatalf("threshold output classification=%q, want hard", got)
	}
}

func TestDefaultPolicyUsesLowSoftThreshold(t *testing.T) {
	if got := defaultPolicy().SoftTPS; got != 75 {
		t.Fatalf("default soft threshold=%v, want 75", got)
	}
}

func TestDefaultPolicyUsesConfigurableProbePrompt(t *testing.T) {
	pol := defaultPolicy()
	if pol.ProbePrompt != "我要去洗车，但洗车店离我家只有5m,我应该走路去还是开车去？请思考后直接给出答案" {
		t.Fatalf("default probe prompt=%q", pol.ProbePrompt)
	}
	if len(pol.ProbeRetryKeywords) != 0 {
		t.Fatalf("default retry keywords=%v, want empty", pol.ProbeRetryKeywords)
	}
}

func TestProbeRetryKeywordMatchesCaseInsensitive(t *testing.T) {
	if !containsProbeRetryKeyword("upstream ROTATE-ME response", []string{"rotate-me"}) {
		t.Fatal("keyword matching should be case-insensitive")
	}
	if containsProbeRetryKeyword("upstream response", []string{"rotate-me"}) {
		t.Fatal("unmatched keyword must not trigger retry")
	}
}

func TestProbeQualityUsesPromptAndKeywordRetry(t *testing.T) {
	invalidateAuthListCache()
	var requests []map[string]any
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		_ = json.Unmarshal(body, &payload)
		requests = append(requests, payload)
		if token := r.Header.Get("Authorization"); token == "Bearer first-token" {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(strings.Repeat("x", 220) + " ROTATE-ME"))
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"thinking\":\"reasoning\",\"content\":\"answer\"}}],\"usage\":{\"completion_tokens\":40}}\n\ndata: [DONE]\n")
	}))
	defer proxy.Close()

	s := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	pol := s.policy()
	pol.ProbePrompt = "请用一句话回答这个自定义问题"
	pol.ProbeRetryKeywords = []string{"rotate-me"}
	if err := s.updatePolicy(pol); err != nil {
		t.Fatal(err)
	}
	auths := map[string]map[string]any{
		"first.json":  {"type": "xai", "email": "first@example.test", "access_token": "first-token", "base_url": proxy.URL, "proxy_url": proxy.URL, "disabled": false},
		"second.json": {"type": "xai", "email": "second@example.test", "access_token": "second-token", "base_url": proxy.URL, "proxy_url": proxy.URL, "disabled": false},
	}
	originalHostCall := hostCall
	hostCall = func(method string, payload []byte) (json.RawMessage, error) {
		switch method {
		case pluginabi.MethodHostAuthList:
			return json.Marshal(hostAuthListResponse{Files: []pluginapi.HostAuthFileEntry{
				{ID: "first.json", AuthIndex: "first.json", Name: "first.json", Provider: "xai", Type: "xai"},
				{ID: "second.json", AuthIndex: "second.json", Name: "second.json", Provider: "xai", Type: "xai"},
			}})
		case pluginabi.MethodHostAuthGet:
			var request map[string]string
			_ = json.Unmarshal(payload, &request)
			raw, ok := auths[request["auth_index"]]
			if !ok {
				return nil, fmt.Errorf("missing auth %s", request["auth_index"])
			}
			body, _ := json.Marshal(raw)
			return json.Marshal(hostAuthGetResponse{AuthIndex: request["auth_index"], Name: request["auth_index"], Path: "/auths/" + request["auth_index"], JSON: body})
		default:
			return nil, fmt.Errorf("unexpected host callback %s", method)
		}
	}
	defer func() {
		hostCall = originalHostCall
		invalidateAuthListCache()
	}()

	result := probeQuality(s, &nodeRecord{ProxyURL: proxy.URL, Enabled: true})
	if result.Classification != "healthy" || result.AuthID != "second.json" {
		t.Fatalf("probe result=%+v, want healthy result from second account", result)
	}
	if len(requests) != 2 {
		t.Fatalf("probe requests=%d, want first error plus one account retry", len(requests))
	}
	messages, ok := requests[0]["messages"].([]any)
	if !ok || len(messages) != 1 {
		t.Fatalf("probe messages=%v", requests[0]["messages"])
	}
	message, _ := messages[0].(map[string]any)
	if message["content"] != pol.ProbePrompt {
		t.Fatalf("probe prompt=%v, want %q", message["content"], pol.ProbePrompt)
	}
}

func TestContainsThinkingBlock(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
		want bool
	}{
		{name: "thinking field", raw: `{"choices":[{"delta":{"thinking":"先判断洗车需要车辆到店"}}]}`, want: true},
		{name: "reasoning content", raw: `{"choices":[{"delta":{"reasoning_content":"drive"}}]}`, want: true},
		{name: "typed block", raw: `{"content":[{"type":"thinking","thinking":"drive"}]}`, want: true},
		{name: "thinking markup", raw: `{"content":"<thinking>drive</thinking>"}`, want: true},
		{name: "plain answer", raw: `{"choices":[{"delta":{"content":"开车去洗车。"}}]}`, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var value any
			if err := json.Unmarshal([]byte(test.raw), &value); err != nil {
				t.Fatal(err)
			}
			if got := containsThinkingBlock(value); got != test.want {
				t.Fatalf("containsThinkingBlock()=%v, want %v", got, test.want)
			}
		})
	}
}

func TestQualityProbeUsesThinkingAsFinalSignal(t *testing.T) {
	withoutThinking := normalizeQualityProbeResult(qualityResult{Classification: "healthy", TPS: 20})
	if withoutThinking.Classification != "hard" || withoutThinking.ErrorKind != "missing_thinking" {
		t.Fatalf("without thinking=%+v, want hard/missing_thinking", withoutThinking)
	}
	withThinking := normalizeQualityProbeResult(qualityResult{Classification: "soft", TPS: 200, Thinking: true})
	if withThinking.Classification != "healthy" || withThinking.Error != "" {
		t.Fatalf("with thinking=%+v, want healthy", withThinking)
	}
}

func TestQuarantineReasonPreservesQualityFailure(t *testing.T) {
	withoutThinking := quarantineReason(qualityResult{
		Classification: "hard",
		TPS:            0.1,
		ErrorKind:      "missing_thinking",
		Error:          "质量探测响应未包含 thinking 块",
	})
	if withoutThinking != "质量探测响应未包含 thinking 块" {
		t.Fatalf("missing-thinking reason=%q, want quality failure", withoutThinking)
	}

	transport := quarantineReason(qualityResult{
		Classification: "hard",
		TPS:            0.1,
		ErrorKind:      "transport_error",
		Error:          "模型探测请求失败: proxyconnect connection refused",
	})
	if transport != "模型探测请求失败: proxyconnect connection refused" {
		t.Fatalf("transport reason=%q, want transport error", transport)
	}

	threshold := quarantineReason(qualityResult{Classification: "hard", TPS: 1000})
	if threshold != "硬阈值 Token/s=1000.0" {
		t.Fatalf("threshold reason=%q, want hard threshold", threshold)
	}
}

func TestSoftObservationStartsOneBackgroundThinkingProbe(t *testing.T) {
	s := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	node, err := s.createNode("soft", "http://127.0.0.1:7951", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	called := make(chan struct{}, 2)
	release := make(chan struct{})
	s.probeQualityFn = func(_ *stateStore, _ *nodeRecord) qualityResult {
		called <- struct{}{}
		<-release
		return qualityResult{Classification: "healthy", Thinking: true, OutputTokens: 80, TPS: 80, AuthEmail: "probe@x.ai"}
	}

	soft := qualityResult{Classification: "soft", OutputTokens: 80, TPS: 80, AuthID: "auth-1", AuthEmail: "soft@x.ai"}
	applyObservation(s, node.ID, "passive", soft)
	if current, _ := s.getNode(node.ID); current.SoftStrikes != 1 {
		t.Fatalf("first soft should only count, strikes=%d", current.SoftStrikes)
	}
	select {
	case <-called:
		t.Fatal("thinking probe started before consecutive_soft was reached")
	case <-time.After(30 * time.Millisecond):
	}

	applyObservation(s, node.ID, "passive", soft)
	if current, _ := s.getNode(node.ID); current.DisabledByGuard {
		t.Fatal("soft signal quarantined node before the background probe")
	}
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("background thinking probe did not start")
	}
	select {
	case extra := <-called:
		_ = extra
		t.Fatal("duplicate soft signal started a second probe")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		current, _ := s.getNode(node.ID)
		if current.LastClassification == "healthy" && current.SoftStrikes == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	current, _ := s.getNode(node.ID)
	t.Fatalf("background probe did not restore healthy state: %+v", current)
}

func TestQualityEventsExposeSourceReasonAndSoftStrikes(t *testing.T) {
	s := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	node, err := s.createNode("event-details", "http://127.0.0.1:7959", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	s.probeQualityFn = func(_ *stateStore, _ *nodeRecord) qualityResult {
		return qualityResult{Classification: "healthy", Thinking: true, OutputTokens: 80, TPS: 80}
	}
	soft := qualityResult{Classification: "soft", OutputTokens: 80, TPS: 80, AuthID: "auth-1"}
	applyObservation(s, node.ID, "passive", soft)
	applyObservation(s, node.ID, "passive", soft)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		events := s.events()
		if len(events) >= 2 {
			var scheduled, completed *guardEvent
			for i := range events {
				event := &events[i]
				switch event.Event {
				case "soft_quality_probe_scheduled":
					scheduled = event
				case "soft_quality_probe_completed":
					completed = event
				}
			}
			if scheduled != nil && completed != nil {
				if scheduled.Source != "passive" || scheduled.SoftStrikes != 2 || scheduled.SoftStrikeLimit != 2 {
					t.Fatalf("scheduled event=%+v, want passive soft count 2/2", *scheduled)
				}
				if !strings.Contains(scheduled.Reason, "软阈值 2/2") {
					t.Fatalf("scheduled reason=%q, want soft threshold count", scheduled.Reason)
				}
				if completed.Source != "active" || completed.SoftStrikes != 2 || completed.SoftStrikeLimit != 2 {
					t.Fatalf("completed event=%+v, want active soft count 2/2", *completed)
				}
				if !strings.Contains(completed.Reason, "主动 thinking 复测通过") {
					t.Fatalf("completed reason=%q, want active probe reason", completed.Reason)
				}
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("missing soft probe events: %+v", s.events())
}

func TestPassiveHardSchedulesThinkingProbeWithoutQuarantine(t *testing.T) {
	s := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	node, err := s.createNode("hard-passive", "http://127.0.0.1:7952", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	// spare healthy node so quarantine would otherwise be allowed
	if _, err := s.createNode("spare", "http://127.0.0.1:7953", true, false, 0); err != nil {
		t.Fatal(err)
	}
	called := make(chan struct{}, 1)
	s.probeQualityFn = func(_ *stateStore, _ *nodeRecord) qualityResult {
		called <- struct{}{}
		return qualityResult{Classification: "healthy", Thinking: true, OutputTokens: 80, TPS: 80}
	}

	hard := qualityResult{Classification: "hard", OutputTokens: 200, TPS: 2000, AuthEmail: "hard@x.ai"}
	applyObservation(s, node.ID, "passive", hard)
	current, _ := s.getNode(node.ID)
	if current.DisabledByGuard {
		t.Fatal("passive hard TPS must not quarantine before thinking probe")
	}
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("passive hard did not schedule thinking probe")
	}
}

func TestActiveHardStillQuarantines(t *testing.T) {
	s := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	node, err := s.createNode("hard-active", "http://127.0.0.1:7954", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.createNode("spare2", "http://127.0.0.1:7955", true, false, 0); err != nil {
		t.Fatal(err)
	}
	hard := qualityResult{
		Classification: "hard",
		OutputTokens:   0,
		TPS:            0.1,
		ErrorKind:      "missing_thinking",
		Error:          "质量探测响应未包含 thinking 块",
	}
	applyObservation(s, node.ID, "active", hard)
	current, _ := s.getNode(node.ID)
	if !current.DisabledByGuard {
		t.Fatal("active hard (missing thinking) must quarantine")
	}
	var quarantined *guardEvent
	for _, event := range s.events() {
		if event.Event == "node_quarantined" {
			copy := event
			quarantined = &copy
		}
	}
	if quarantined == nil || quarantined.Source != "active" || quarantined.Reason != "质量探测响应未包含 thinking 块" {
		t.Fatalf("quarantine event=%v, want active source and explicit reason", quarantined)
	}
}

func TestQualityObservationTimeExcludesConnectivityProbe(t *testing.T) {
	s := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	node, err := s.createNode("timing", "http://127.0.0.1:7958", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	observedAt := float64(time.Now().Add(-2 * time.Hour).Unix())
	probeAt := float64(time.Now().Add(-time.Hour).Unix())
	if _, err := s.updateNode(node.ID, func(value *nodeRecord) error {
		value.LastObservedAt = observedAt
		value.LastProbeAt = probeAt
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	originalConnectivity := probeConnectivityFn
	probeConnectivityFn = func(string) (string, int64, error) {
		return "198.51.100.8", 12, nil
	}
	defer func() { probeConnectivityFn = originalConnectivity }()

	if _, err := runNodeConnectivity(s, node.ID); err != nil {
		t.Fatal(err)
	}
	current, _ := s.getNode(node.ID)
	if current.LastObservedAt != observedAt {
		t.Fatalf("connectivity changed last observed time from %v to %v", observedAt, current.LastObservedAt)
	}
	if current.LastProbeAt != probeAt {
		t.Fatalf("connectivity changed last quality probe time from %v to %v", probeAt, current.LastProbeAt)
	}

	s.probeQualityFn = func(_ *stateStore, _ *nodeRecord) qualityResult {
		return qualityResult{Classification: "healthy", Thinking: true, OutputTokens: 80, TPS: 80}
	}
	if _, err := runNodeQuality(s, node.ID); err != nil {
		t.Fatal(err)
	}
	current, _ = s.getNode(node.ID)
	if current.LastObservedAt <= observedAt {
		t.Fatalf("quality did not advance last observed time: before=%v after=%v", observedAt, current.LastObservedAt)
	}
	if current.LastProbeAt <= probeAt {
		t.Fatalf("quality did not advance last quality probe time: before=%v after=%v", probeAt, current.LastProbeAt)
	}
}

func TestWorkerPollIntervalUsesPassivePollSeconds(t *testing.T) {
	s := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	pol := s.policy()
	pol.PassivePollSec = 7
	if err := s.updatePolicy(pol); err != nil {
		t.Fatal(err)
	}
	if got := workerPollInterval(s); got != 7*time.Second {
		t.Fatalf("workerPollInterval=%v, want 7s", got)
	}
}

func TestUpdatingQuarantineSecondsReschedulesExistingQuarantinedNodes(t *testing.T) {
	s := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	quarantined, err := s.createNode("quarantined", "http://127.0.0.1:7956", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	healthy, err := s.createNode("healthy", "http://127.0.0.1:7957", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	oldUntil := float64(time.Now().Add(-time.Minute).Unix())
	if _, err := s.updateNode(quarantined.ID, func(node *nodeRecord) error {
		node.DisabledByGuard = true
		node.QuarantinedUntil = oldUntil
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	pol := s.policy()
	pol.QuarantineSec = 3600
	if err := s.updatePolicy(pol); err != nil {
		t.Fatal(err)
	}

	current, _ := s.getNode(quarantined.ID)
	minimumUntil := float64(time.Now().Add(3590 * time.Second).Unix())
	if current.QuarantinedUntil < minimumUntil {
		t.Fatalf("quarantine deadline=%v, want at least ~3600 seconds from now", current.QuarantinedUntil)
	}
	if current.QuarantinedUntil == oldUntil {
		t.Fatal("quarantine deadline was not updated")
	}
	untouched, _ := s.getNode(healthy.ID)
	if untouched.DisabledByGuard || untouched.QuarantinedUntil != 0 {
		t.Fatalf("healthy node changed during policy update: %+v", untouched)
	}

	deadline := current.QuarantinedUntil
	if err := s.updatePolicy(pol); err != nil {
		t.Fatal(err)
	}
	current, _ = s.getNode(quarantined.ID)
	if current.QuarantinedUntil != deadline {
		t.Fatalf("saving unchanged policy moved deadline from %v to %v", deadline, current.QuarantinedUntil)
	}
}

func TestQuarantinedNoAccountSchedulesNextRetest(t *testing.T) {
	s := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	node, err := s.createNode("Node 040", "http://127.0.0.1:7951", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.updateNode(node.ID, func(value *nodeRecord) error {
		value.DisabledByGuard = true
		value.QuarantinedUntil = float64(time.Now().Add(-time.Minute).Unix())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s.probeQualityFn = func(_ *stateStore, _ *nodeRecord) qualityResult {
		return qualityResult{
			Classification: "error",
			ErrorKind:      "no_account",
			Error:          "没有可用的 CPA xAI 账号",
		}
	}
	if _, err := runNodeQuality(s, node.ID); err != nil {
		t.Fatal(err)
	}

	current, _ := s.getNode(node.ID)
	if current.LastClassification != "ignored" {
		t.Fatalf("no-account probe classification=%q, want ignored", current.LastClassification)
	}
	if current.LastReason != "没有可用的 CPA xAI 账号 · 账号池恢复后重试" {
		t.Fatalf("no-account probe reason=%q", current.LastReason)
	}
	if !current.DisabledByGuard {
		t.Fatal("no-account retest must keep the node quarantined")
	}
	if current.QuarantinedUntil <= float64(time.Now().Unix()) {
		t.Fatalf("no-account retest did not schedule a future retry: until=%v", current.QuarantinedUntil)
	}
	if current.ErrorStrikes != 0 {
		t.Fatalf("no-account retest must not spend transport error strikes: %d", current.ErrorStrikes)
	}
}

func TestManualDisabledAuthIsNotRestored(t *testing.T) {
	if isGuardDisabledAuth(authFile{Disabled: true, Raw: map[string]any{"disabled_reason": "operator: maintenance"}}) {
		t.Fatal("operator-disabled auth must not be treated as guard-managed")
	}
}

func TestSchedulerSkipsCoolingStatuses(t *testing.T) {
	for _, status := range []string{"disabled", "unavailable", "error", "cooling", "pending", "refreshing", "future-state"} {
		if schedulerCandidateAvailable(pluginapi.SchedulerAuthCandidate{Status: status}) {
			t.Fatalf("status %q should not be selected", status)
		}
	}
	for _, status := range []string{"", "active", "ready"} {
		if !schedulerCandidateAvailable(pluginapi.SchedulerAuthCandidate{Status: status}) {
			t.Fatalf("status %q should be selectable", status)
		}
	}
}

func TestMigrationFailsClosedAndVerifiesHostAuthSave(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	bad, err := store.createNode("bad", "http://127.0.0.1:7951", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	good, err := store.createNode("good", "http://127.0.0.1:7952", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.updateNode(good.ID, func(node *nodeRecord) error {
		node.LastClassification = "healthy"
		node.LastProbeAt = float64(time.Now().Unix())
		node.ExitIP = "198.51.100.2"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.updateNode(bad.ID, func(node *nodeRecord) error {
		node.ExitIP = "198.51.100.1"
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	auths := map[string]map[string]any{
		"bad.json": {
			"type": "xai", "email": "bad@example.test", "access_token": "bad-token", "proxy_url": bad.ProxyURL, "disabled": false,
		},
		"good.json": {
			"type": "xai", "email": "good@example.test", "access_token": "good-token", "proxy_url": good.ProxyURL, "disabled": false,
		},
		"manual.json": {
			"type": "xai", "email": "manual@example.test", "access_token": "manual-token", "proxy_url": bad.ProxyURL, "disabled": true, "disabled_reason": "operator maintenance",
		},
	}
	originalHostCall := hostCall
	hostCall = func(method string, payload []byte) (json.RawMessage, error) {
		switch method {
		case pluginabi.MethodHostAuthList:
			entries := make([]pluginapi.HostAuthFileEntry, 0, len(auths))
			for name, raw := range auths {
				disabled, _ := raw["disabled"].(bool)
				entries = append(entries, pluginapi.HostAuthFileEntry{ID: name, AuthIndex: name, Name: name, Provider: "xai", Type: "xai", Disabled: disabled})
			}
			return json.Marshal(hostAuthListResponse{Files: entries})
		case pluginabi.MethodHostAuthGet:
			var request map[string]string
			_ = json.Unmarshal(payload, &request)
			name := request["auth_index"]
			if name == "" {
				name = request["name"]
			}
			raw, ok := auths[name]
			if !ok {
				return nil, fmt.Errorf("auth not found: %s", name)
			}
			body, _ := json.Marshal(raw)
			return json.Marshal(hostAuthGetResponse{AuthIndex: name, Name: name, Path: "/auths/" + name, JSON: body})
		case pluginabi.MethodHostAuthSave:
			var request struct {
				Name string          `json:"name"`
				JSON json.RawMessage `json:"json"`
			}
			if err := json.Unmarshal(payload, &request); err != nil {
				return nil, err
			}
			updated := map[string]any{}
			if err := json.Unmarshal(request.JSON, &updated); err != nil {
				return nil, err
			}
			auths[request.Name] = updated
			return json.Marshal(pluginapi.HostAuthSaveResponse{Name: request.Name, Path: "/auths/" + request.Name})
		default:
			return nil, fmt.Errorf("unexpected host callback %s", method)
		}
	}
	defer func() {
		hostCall = originalHostCall
		authProxyMu.Lock()
		authProxyCache = nil
		authProxyAt = time.Time{}
		authProxyMu.Unlock()
		invalidateAuthListCache()
	}()

	if err := migrateAuthsOffNode(store, bad); err != nil {
		t.Fatalf("migrateAuthsOffNode() error = %v", err)
	}
	if got := auths["bad.json"]["proxy_url"]; got != good.ProxyURL {
		t.Fatalf("bad auth proxy=%q, want healthy proxy", got)
	}
	if disabled, _ := auths["bad.json"]["disabled"].(bool); disabled {
		t.Fatal("migrated auth remains disabled")
	}
	if got := auths["manual.json"]["proxy_url"]; got != bad.ProxyURL {
		t.Fatalf("manual auth proxy=%q, want unchanged bad proxy", got)
	}
	if disabled, _ := auths["manual.json"]["disabled"].(bool); !disabled {
		t.Fatal("manual disabled auth was re-enabled")
	}
}

func TestSchedulerSkipsQuarantinedNode(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	bad, err := store.createNode("bad", "http://127.0.0.1:7951", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	good, err := store.createNode("good", "http://127.0.0.1:7952", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.updateNode(bad.ID, func(node *nodeRecord) error { node.DisabledByGuard = true; return nil }); err != nil {
		t.Fatal(err)
	}
	authProxyMu.Lock()
	authProxyCache = map[string]string{"auth-bad": bad.ProxyURL, "auth-good": good.ProxyURL}
	authProxyAt = time.Now()
	authProxyMu.Unlock()
	rawRequest, _ := json.Marshal(pluginapi.SchedulerPickRequest{
		Provider: "xai",
		Candidates: []pluginapi.SchedulerAuthCandidate{
			{ID: "auth-bad", Provider: "xai"},
			{ID: "auth-good", Provider: "xai"},
		},
	})
	raw, err := handleSchedulerPick(rawRequest)
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil || !env.OK {
		t.Fatalf("scheduler envelope=%s err=%v", raw, err)
	}
	var response pluginapi.SchedulerPickResponse
	if err := json.Unmarshal(env.Result, &response); err != nil {
		t.Fatal(err)
	}
	if !response.Handled || response.AuthID != "auth-good" {
		t.Fatalf("scheduler response=%+v", response)
	}
}

func TestRequestInterceptorRejectsQuarantinedAuth(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	node, err := store.createNode("bad", "http://127.0.0.1:7951", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.updateNode(node.ID, func(value *nodeRecord) error { value.DisabledByGuard = true; return nil }); err != nil {
		t.Fatal(err)
	}
	authProxyMu.Lock()
	authProxyCache = map[string]string{"auth-bad": node.ProxyURL}
	authProxyAt = time.Now()
	authProxyMu.Unlock()
	rawRequest, _ := json.Marshal(pluginapi.RequestInterceptRequest{Metadata: map[string]any{"selected_auth_id": "auth-bad"}})
	raw, err := handleRequestIntercept(rawRequest, true)
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	_ = json.Unmarshal(raw, &env)
	var response pluginapi.RequestInterceptResponse
	_ = json.Unmarshal(env.Result, &response)
	if !response.Terminate || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("interceptor response=%+v", response)
	}
}

func TestClassifyTPS(t *testing.T) {
	if classifyTPS(1200, 500, 1000) != "hard" {
		t.Fatal("expected hard")
	}
	if classifyTPS(600, 500, 1000) != "soft" {
		t.Fatal("expected soft")
	}
	if classifyTPS(100, 500, 1000) != "healthy" {
		t.Fatal("expected healthy")
	}
}

func TestStoreNodeCRUD(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := newStateStore(path)
	n, err := s.createNode("ch-1", "http://127.0.0.1:7951", true, false, 200)
	if err != nil {
		t.Fatal(err)
	}
	if n.ID == "" || n.ProxyURL == "" {
		t.Fatalf("bad node %#v", n)
	}
	pub := publicNode(n)
	if _, ok := pub["proxy_url"]; ok {
		t.Fatal("public node must not expose proxy_url")
	}
	if pub["hasProxy"] != true {
		t.Fatal("hasProxy")
	}
	list := s.listNodes()
	if len(list) != 1 {
		t.Fatalf("len=%d", len(list))
	}
	// reload
	s2 := newStateStore(path)
	n2, ok := s2.getNode(n.ID)
	if !ok || n2.ProxyURL != "http://127.0.0.1:7951" {
		t.Fatalf("reload failed %#v", n2)
	}
	_ = s2.deleteNodes([]string{n.ID})
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestStoreCreateNodesIsAllOrNothing(t *testing.T) {
	s := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	created, err := s.createNodes([]nodeCreateInput{
		{Name: "a", ProxyURL: "http://127.0.0.1:7951", Enabled: true, AccountCapacity: 100},
		{Name: "b", ProxyURL: "http://127.0.0.1:7952", Enabled: true, ProxyPool: true, AccountCapacity: 120},
	})
	if err != nil || len(created) != 2 || len(s.listNodes()) != 2 {
		t.Fatalf("created=%d nodes=%d err=%v", len(created), len(s.listNodes()), err)
	}
	if _, err := s.createNodes([]nodeCreateInput{
		{Name: "valid", ProxyURL: "http://127.0.0.1:7953", Enabled: true},
		{Name: "invalid", ProxyURL: "", Enabled: true},
	}); err == nil {
		t.Fatal("expected invalid import to fail")
	}
	if len(s.listNodes()) != 2 {
		t.Fatal("invalid batch must not create partial nodes")
	}
}

func TestRenderStatusPage(t *testing.T) {
	page := strings.Replace(pageTemplate, "/*__HALLMARK_TOKENS__*/", tokenCSS, 1)
	for _, want := range []string{"出口守护", "纯 CPA", "data-batch=\"enable\"", "重平衡账号", "批量添加", "/nodes/import", "/nodes/export", "页面每 15 秒刷新", "node-status-filter", "全部状态", "nodeStatusKey", "dedupe-exit-ip", "按出口 IP 剔重", "duplicateNodesByExitIP", "export-nodes", "egress-proxies.txt", "当前结果", "已绑定账号会随节点删除而解绑", "最短生成窗口", "policy-retry-keywords", "policy-prompt", "X-Grok2API-Egress-UI", "触发：", "手动触发", "定时任务触发", "原因：", "软阈值计数", "soft_strikes", "sourceName", "triggerName"} {
		if !strings.Contains(page, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Contains(page, "/*__HALLMARK_TOKENS__*/") {
		t.Fatal("tokens not replaced in test helper path only")
	}
	if strings.Contains(page, "guard.last_observed_at || guard.last_probe_at") {
		t.Fatal("connectivity probe must not be used as the last observed time")
	}
}

func TestUIProxyRejectsMissingHeader(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "s.json"))
	body, _ := json.Marshal(uiProxyRequest{Method: http.MethodGet, Path: "/nodes"})
	raw, err := handleUIProxy(managementRequest{Method: http.MethodPost, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"StatusCode":403`) {
		t.Fatalf("got %s", raw)
	}
}

func TestDispatchNodesList(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "s.json"))
	_, _ = store.createNode("a", "http://127.0.0.1:1", true, false, 0)
	headers := make(http.Header)
	headers.Set("X-Grok2API-Egress-UI", "1")
	body, _ := json.Marshal(uiProxyRequest{Method: http.MethodGet, Path: "/nodes"})
	raw, err := handleUIProxy(managementRequest{Method: http.MethodPost, Headers: headers, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	_ = json.Unmarshal(raw, &env)
	var resp managementResponse
	_ = json.Unmarshal(env.Result, &resp)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d %s", resp.StatusCode, resp.Body)
	}
	if !strings.Contains(string(resp.Body), `"name":"a"`) {
		t.Fatalf("body %s", resp.Body)
	}
}

func TestDispatchNodesExportUsesRequestedOrderAndKeepsListRedacted(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "s.json"))
	first, err := store.createNode("first", "http://user:first@127.0.0.1:7951", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.createNode("second", "socks5h://user:second@127.0.0.1:7952", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	headers := make(http.Header)
	headers.Set("X-Grok2API-Egress-UI", "1")
	call := func(method, path string, payload any) managementResponse {
		rawBody, _ := json.Marshal(payload)
		requestBody, _ := json.Marshal(uiProxyRequest{Method: method, Path: path, Body: rawBody})
		raw, callErr := handleUIProxy(managementRequest{Method: http.MethodPost, Headers: headers, Body: requestBody})
		if callErr != nil {
			t.Fatal(callErr)
		}
		var env envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatal(err)
		}
		var response managementResponse
		if err := json.Unmarshal(env.Result, &response); err != nil {
			t.Fatal(err)
		}
		return response
	}

	response := call(http.MethodPost, "/nodes/export", map[string]any{
		"ids": []string{second.ID, first.ID, second.ID, "missing"},
	})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("export status=%d body=%s", response.StatusCode, response.Body)
	}
	var exported struct {
		Data struct {
			Content string `json:"content"`
			Count   int    `json:"count"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body, &exported); err != nil {
		t.Fatal(err)
	}
	wantContent := "socks5h://user:second@127.0.0.1:7952\nhttp://user:first@127.0.0.1:7951\n"
	if exported.Data.Content != wantContent || exported.Data.Count != 2 {
		t.Fatalf("export=%+v, want content %q and count 2", exported.Data, wantContent)
	}

	list := call(http.MethodGet, "/nodes", nil)
	if list.StatusCode != http.StatusOK || strings.Contains(string(list.Body), "user:first") || strings.Contains(string(list.Body), "user:second") {
		t.Fatalf("node list leaked proxy URL: status=%d body=%s", list.StatusCode, list.Body)
	}

	for _, ids := range []any{[]string{}, make([]string, 501)} {
		invalid := call(http.MethodPost, "/nodes/export", map[string]any{"ids": ids})
		if invalid.StatusCode != http.StatusBadRequest || strings.Contains(string(invalid.Body), "user:") {
			t.Fatalf("invalid export status=%d body=%s", invalid.StatusCode, invalid.Body)
		}
	}
}

func TestDispatchNodesImportRedactsProxyURLs(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "s.json"))
	headers := make(http.Header)
	headers.Set("X-Grok2API-Egress-UI", "1")
	requestBody, _ := json.Marshal(map[string]any{
		"items": []map[string]any{
			{"name": "fixed-a", "proxyURL": "http://user:pass@127.0.0.1:7951", "accountCapacity": 100},
			{"proxy_url": "http://user:pass@127.0.0.1:7952", "proxy_pool": true},
		},
	})
	body, _ := json.Marshal(uiProxyRequest{Method: http.MethodPost, Path: "/nodes/import", Body: requestBody})
	raw, err := handleUIProxy(managementRequest{Method: http.MethodPost, Headers: headers, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	_ = json.Unmarshal(raw, &env)
	var resp managementResponse
	_ = json.Unmarshal(env.Result, &resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(resp.Body), `"created":2`) {
		t.Fatalf("status=%d body=%s", resp.StatusCode, resp.Body)
	}
	if strings.Contains(string(resp.Body), "user:pass") || strings.Contains(string(resp.Body), "proxy_url") {
		t.Fatalf("response leaked proxy URL: %s", resp.Body)
	}
	if len(store.listNodes()) != 2 {
		t.Fatalf("node count=%d", len(store.listNodes()))
	}
}

func TestAuthListCacheAvoidsRepeatedHostGets(t *testing.T) {
	invalidateAuthListCache()
	calls := map[string]int{}
	auths := map[string]map[string]any{
		"a.json": {"type": "xai", "email": "a@example.test", "access_token": "t", "proxy_url": "http://127.0.0.1:1", "disabled": false},
		"b.json": {"type": "xai", "email": "b@example.test", "access_token": "t", "proxy_url": "http://127.0.0.1:2", "disabled": false},
	}
	original := hostCall
	hostCall = func(method string, payload []byte) (json.RawMessage, error) {
		calls[method]++
		switch method {
		case pluginabi.MethodHostAuthList:
			entries := make([]pluginapi.HostAuthFileEntry, 0, len(auths))
			for name, raw := range auths {
				disabled, _ := raw["disabled"].(bool)
				entries = append(entries, pluginapi.HostAuthFileEntry{ID: name, AuthIndex: name, Name: name, Provider: "xai", Type: "xai", Disabled: disabled})
			}
			return json.Marshal(hostAuthListResponse{Files: entries})
		case pluginabi.MethodHostAuthGet:
			var request map[string]string
			_ = json.Unmarshal(payload, &request)
			name := request["auth_index"]
			if name == "" {
				name = request["name"]
			}
			raw, ok := auths[name]
			if !ok {
				return nil, fmt.Errorf("missing %s", name)
			}
			body, _ := json.Marshal(raw)
			return json.Marshal(hostAuthGetResponse{AuthIndex: name, Name: name, Path: "/auths/" + name, JSON: body})
		case pluginabi.MethodHostAuthSave:
			var request struct {
				Name string          `json:"name"`
				JSON json.RawMessage `json:"json"`
			}
			if err := json.Unmarshal(payload, &request); err != nil {
				return nil, err
			}
			updated := map[string]any{}
			if err := json.Unmarshal(request.JSON, &updated); err != nil {
				return nil, err
			}
			auths[request.Name] = updated
			return json.Marshal(pluginapi.HostAuthSaveResponse{Name: request.Name, Path: "/auths/" + request.Name})
		default:
			return nil, fmt.Errorf("unexpected %s", method)
		}
	}
	defer func() {
		hostCall = original
		invalidateAuthListCache()
		authProxyMu.Lock()
		authProxyCache = nil
		authProxyAt = time.Time{}
		authProxyMu.Unlock()
	}()

	first, err := listAuthFiles()
	if err != nil || len(first) != 2 {
		t.Fatalf("first list: n=%d err=%v", len(first), err)
	}
	if calls[pluginabi.MethodHostAuthList] != 1 || calls[pluginabi.MethodHostAuthGet] != 2 {
		t.Fatalf("cold list host calls list=%d get=%d, want 1/2", calls[pluginabi.MethodHostAuthList], calls[pluginabi.MethodHostAuthGet])
	}
	for i := 0; i < 5; i++ {
		if _, err := listAuthFiles(); err != nil {
			t.Fatal(err)
		}
	}
	if calls[pluginabi.MethodHostAuthList] != 1 || calls[pluginabi.MethodHostAuthGet] != 2 {
		t.Fatalf("warm path re-hit host: list=%d get=%d", calls[pluginabi.MethodHostAuthList], calls[pluginabi.MethodHostAuthGet])
	}
	if err := saveAuthFile("a.json", map[string]any{
		"type": "xai", "email": "a@example.test", "access_token": "t", "proxy_url": "http://127.0.0.1:9", "disabled": false,
	}); err != nil {
		t.Fatal(err)
	}
	// patched cache must reflect new proxy without another full list/get sweep
	got, err := listAuthFiles()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range got {
		if a.Name == "a.json" && a.ProxyURL == "http://127.0.0.1:9" {
			found = true
		}
	}
	if !found {
		t.Fatal("cache was not patched after save")
	}
	if calls[pluginabi.MethodHostAuthList] != 1 || calls[pluginabi.MethodHostAuthGet] != 2 {
		t.Fatalf("save+list triggered refetch list=%d get=%d", calls[pluginabi.MethodHostAuthList], calls[pluginabi.MethodHostAuthGet])
	}
}

func TestDebouncedPersistCoalescesStats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := newStateStore(path)
	s.flushDelay = 50 * time.Millisecond
	for i := 0; i < 20; i++ {
		s.bumpStat("passive", "healthy", 10)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var st guardState
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	if st.Stats.Passive.Total != 20 {
		t.Fatalf("passive total=%d want 20", st.Stats.Passive.Total)
	}
}

func TestAuthListCacheKeepsWarmPoolWhenHostReportsEmpty(t *testing.T) {
	invalidateAuthListCache()
	empty := false
	auths := map[string]map[string]any{
		"a.json": {"type": "xai", "email": "a@example.test", "access_token": "t", "proxy_url": "http://127.0.0.1:1", "disabled": false},
		"b.json": {"type": "xai", "email": "b@example.test", "access_token": "t", "proxy_url": "http://127.0.0.1:2", "disabled": false},
	}
	original := hostCall
	hostCall = func(method string, payload []byte) (json.RawMessage, error) {
		switch method {
		case pluginabi.MethodHostAuthList:
			if empty {
				// CPA auth reload window: host briefly reports zero auth files.
				return json.Marshal(hostAuthListResponse{Files: []pluginapi.HostAuthFileEntry{}})
			}
			entries := make([]pluginapi.HostAuthFileEntry, 0, len(auths))
			for name := range auths {
				entries = append(entries, pluginapi.HostAuthFileEntry{ID: name, AuthIndex: name, Name: name, Provider: "xai", Type: "xai"})
			}
			return json.Marshal(hostAuthListResponse{Files: entries})
		case pluginabi.MethodHostAuthGet:
			var request map[string]string
			_ = json.Unmarshal(payload, &request)
			raw, ok := auths[request["auth_index"]]
			if !ok {
				return nil, fmt.Errorf("missing %s", request["auth_index"])
			}
			body, _ := json.Marshal(raw)
			return json.Marshal(hostAuthGetResponse{AuthIndex: request["auth_index"], Name: request["auth_index"], Path: "/auths/" + request["auth_index"], JSON: body})
		default:
			return nil, fmt.Errorf("unexpected %s", method)
		}
	}
	defer func() {
		hostCall = original
		invalidateAuthListCache()
	}()

	if warm, err := listAuthFiles(); err != nil || len(warm) != 2 {
		t.Fatalf("warm list: n=%d err=%v", len(warm), err)
	}

	empty = true
	got, err := listAuthFilesFresh()
	if err != nil || len(got) != 2 {
		t.Fatalf("transient empty host list dropped the warm pool: n=%d err=%v", len(got), err)
	}
	// A quality probe must still find candidates during that window.
	node := &nodeRecord{ProxyURL: "http://127.0.0.1:1"}
	candidates, err := listAuthsForNode(node, 8)
	if err != nil || len(candidates) == 0 {
		t.Fatalf("listAuthsForNode during reload window: n=%d err=%v", len(candidates), err)
	}

	// Once the host keeps reporting empty past the grace window, accept it.
	authListMu.Lock()
	authListGoodAt = time.Now().Add(-2 * authListEmptyGrace)
	authListMu.Unlock()
	if got, err := listAuthFilesFresh(); err != nil || len(got) != 0 {
		t.Fatalf("persistent empty pool not adopted: n=%d err=%v", len(got), err)
	}
}

func TestAuthSelectionRefreshesEmptyCacheAndBorrowsFromPool(t *testing.T) {
	invalidateAuthListCache()
	auths := map[string]map[string]any{}
	original := hostCall
	hostCall = func(method string, payload []byte) (json.RawMessage, error) {
		switch method {
		case pluginabi.MethodHostAuthList:
			entries := make([]pluginapi.HostAuthFileEntry, 0, len(auths))
			for name := range auths {
				entries = append(entries, pluginapi.HostAuthFileEntry{ID: name, AuthIndex: name, Name: name, Provider: "xai", Type: "xai"})
			}
			return json.Marshal(hostAuthListResponse{Files: entries})
		case pluginabi.MethodHostAuthGet:
			var request map[string]string
			_ = json.Unmarshal(payload, &request)
			raw, ok := auths[request["auth_index"]]
			if !ok {
				return nil, fmt.Errorf("missing auth %s", request["auth_index"])
			}
			body, _ := json.Marshal(raw)
			return json.Marshal(hostAuthGetResponse{AuthIndex: request["auth_index"], Name: request["auth_index"], JSON: body})
		default:
			return nil, fmt.Errorf("unexpected host callback %s", method)
		}
	}
	defer func() {
		hostCall = original
		invalidateAuthListCache()
	}()

	// Reproduce the NC race: an empty host snapshot is cached before the pool
	// finishes loading.
	if got, err := listAuthFiles(); err != nil || len(got) != 0 {
		t.Fatalf("initial empty pool: n=%d err=%v", len(got), err)
	}
	auths["pool-a.json"] = map[string]any{
		"type": "xai", "email": "pool-a@example.test", "access_token": "token-a",
		"proxy_url": "http://127.0.0.1:9001", "disabled": false,
	}
	auths["pool-b.json"] = map[string]any{
		"type": "xai", "email": "pool-b@example.test", "access_token": "token-b",
		"proxy_url": "http://127.0.0.1:9002", "disabled": false,
	}

	// The target has no bound account; selection must refresh the pool and
	// borrow an account from another node instead of reporting no-account.
	candidates, err := listAuthsForNode(&nodeRecord{
		ID: "target", Name: "Node 027", ProxyURL: "http://127.0.0.1:9027", Enabled: true,
	}, 1)
	if err != nil || len(candidates) != 1 {
		t.Fatalf("pool fallback: candidates=%d err=%v", len(candidates), err)
	}
	if candidates[0].Name != "pool-a.json" && candidates[0].Name != "pool-b.json" {
		t.Fatalf("borrowed account=%q, want an account from the global pool", candidates[0].Name)
	}
}

func TestQualityEventsRecordManualAndScheduledTrigger(t *testing.T) {
	s := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	store = s
	node, err := s.createNode("Node 027", "http://127.0.0.1:9027", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	s.probeQualityFn = func(_ *stateStore, _ *nodeRecord) qualityResult {
		return qualityResult{Classification: "healthy", Thinking: true, OutputTokens: 80, TPS: 80}
	}

	if _, err := dispatchAPI(http.MethodPost, "/nodes/"+node.ID+"/quality-test", nil, nil); err != nil {
		t.Fatal(err)
	}
	events := s.events()
	if len(events) == 0 || events[len(events)-1].Event != "quality_probe_completed" {
		t.Fatalf("manual quality event missing: %+v", events)
	}
	if got := events[len(events)-1].Trigger; got != "manual" {
		t.Fatalf("manual trigger=%q, want manual", got)
	}

	if _, err := runNodeQuality(s, node.ID); err != nil {
		t.Fatal(err)
	}
	events = s.events()
	if got := events[len(events)-1].Trigger; got != "scheduled" {
		t.Fatalf("scheduled trigger=%q, want scheduled", got)
	}
}

func TestIsolationRetestExcludesDisabledAccounts(t *testing.T) {
	invalidateAuthListCache()
	// After quarantine, all token-bearing credentials in this fixture are
	// disabled. Neither normal selection nor isolation retest may bypass that
	// account-level flag.
	auths := map[string]map[string]any{
		"disabled-a.json": {
			"type": "xai", "email": "a@example.test", "access_token": "token-a",
			"proxy_url": "http://127.0.0.1:9001", "disabled": true, "disabled_reason": "egress-guard 隔离中",
		},
		"disabled-b.json": {
			"type": "xai", "email": "b@example.test", "access_token": "token-b",
			"proxy_url": "http://127.0.0.1:9002", "disabled": true, "disabled_reason": "egress-guard 降智隔离",
		},
		"no-token.json": {
			"type": "xai", "email": "empty@example.test", "access_token": "",
			"proxy_url": "http://127.0.0.1:9003", "disabled": false,
		},
	}
	original := hostCall
	hostCall = func(method string, payload []byte) (json.RawMessage, error) {
		switch method {
		case pluginabi.MethodHostAuthList:
			entries := make([]pluginapi.HostAuthFileEntry, 0, len(auths))
			for name, raw := range auths {
				disabled, _ := raw["disabled"].(bool)
				entries = append(entries, pluginapi.HostAuthFileEntry{
					ID: name, AuthIndex: name, Name: name, Provider: "xai", Type: "xai", Disabled: disabled,
				})
			}
			return json.Marshal(hostAuthListResponse{Files: entries})
		case pluginabi.MethodHostAuthGet:
			var request map[string]string
			_ = json.Unmarshal(payload, &request)
			name := request["auth_index"]
			if name == "" {
				name = request["name"]
			}
			raw, ok := auths[name]
			if !ok {
				return nil, fmt.Errorf("missing %s", name)
			}
			body, _ := json.Marshal(raw)
			return json.Marshal(hostAuthGetResponse{AuthIndex: name, Name: name, Path: "/auths/" + name, JSON: body})
		default:
			return nil, fmt.Errorf("unexpected %s", method)
		}
	}
	defer func() {
		hostCall = original
		invalidateAuthListCache()
	}()

	quarantined := &nodeRecord{ProxyURL: "http://127.0.0.1:9001", DisabledByGuard: true}
	if got, err := listAuthsForNode(quarantined, 8); err == nil || len(got) != 0 {
		t.Fatalf("enabled-only selection should be empty after isolation: n=%d err=%v", len(got), err)
	}

	pool, err := listAnyAuthsForIsolationRetest(8)
	if err == nil || len(pool) != 0 {
		t.Fatalf("isolation retest must reject disabled accounts: n=%d err=%v", len(pool), err)
	}

	// probeQuality candidate path: DisabledByGuard must not turn disabled
	// credentials into a recovery candidate.
	candidates, err := listAuthsForNode(quarantined, 8)
	if err == nil || len(candidates) > 0 {
		t.Fatal("precondition failed: expected no enabled candidates")
	}
	if quarantined.DisabledByGuard {
		if pool, poolErr := listAnyAuthsForIsolationRetest(8); poolErr == nil || len(pool) > 0 {
			t.Fatalf("isolation retest must not bypass disabled accounts: n=%d err=%v", len(pool), poolErr)
		}
	}

	// Enabled accounts remain eligible even when they are not bound to the
	// quarantined node.
	auths["enabled-c.json"] = map[string]any{
		"type": "xai", "email": "c@example.test", "access_token": "token-c",
		"proxy_url": "http://127.0.0.1:9003", "disabled": false,
	}
	invalidateAuthListCache()
	pool, err = listAnyAuthsForIsolationRetest(8)
	if err != nil || len(pool) != 1 || pool[0].Name != "enabled-c.json" || pool[0].Disabled {
		t.Fatalf("enabled isolation retest pool: n=%d err=%v, want enabled-c.json only", len(pool), err)
	}
}

func TestPolicyAcceptsCamelCaseDisableAuthOnHard(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "s.json"))
	put := func(v bool) {
		body, _ := json.Marshal(map[string]any{"disableAuthOnHard": v})
		raw, err := dispatchAPI(http.MethodPut, "/policy", nil, body)
		if err != nil {
			t.Fatal(err)
		}
		var env envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatal(err)
		}
		var resp managementResponse
		if err := json.Unmarshal(env.Result, &resp); err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d body=%s", resp.StatusCode, resp.Body)
		}
	}
	put(false)
	if store.policy().DisableAuthOnHard {
		t.Fatal("camelCase disableAuthOnHard=false was ignored")
	}
	put(true)
	if !store.policy().DisableAuthOnHard {
		t.Fatal("camelCase disableAuthOnHard=true was ignored")
	}
}

func TestPolicyAcceptsProbePromptAndRetryKeywords(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	body, _ := json.Marshal(map[string]any{
		"probePrompt":        "  自定义探测问题  ",
		"probeRetryKeywords": " rotate-me \n\n AUTH-FAIL \n rotate-me ",
	})
	raw, err := dispatchAPI(http.MethodPut, "/policy", nil, body)
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	var resp managementResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, resp.Body)
	}
	pol := store.policy()
	if pol.ProbePrompt != "自定义探测问题" {
		t.Fatalf("probe prompt=%q", pol.ProbePrompt)
	}
	if got, want := strings.Join(pol.ProbeRetryKeywords, "|"), "rotate-me|AUTH-FAIL"; got != want {
		t.Fatalf("probe retry keywords=%q, want %q", got, want)
	}
}

func installAuthFixture(t *testing.T, auths map[string]map[string]any) {
	t.Helper()
	originalHostCall := hostCall
	invalidateAuthListCache()
	hostCall = func(method string, payload []byte) (json.RawMessage, error) {
		switch method {
		case pluginabi.MethodHostAuthList:
			entries := make([]pluginapi.HostAuthFileEntry, 0, len(auths))
			for name, raw := range auths {
				disabled, _ := raw["disabled"].(bool)
				entries = append(entries, pluginapi.HostAuthFileEntry{
					ID: name, AuthIndex: name, Name: name, Provider: "xai", Type: "xai", Disabled: disabled,
				})
			}
			return json.Marshal(hostAuthListResponse{Files: entries})
		case pluginabi.MethodHostAuthGet:
			var request map[string]string
			if err := json.Unmarshal(payload, &request); err != nil {
				return nil, err
			}
			name := request["auth_index"]
			if name == "" {
				name = request["name"]
			}
			raw, ok := auths[name]
			if !ok {
				return nil, fmt.Errorf("auth not found: %s", name)
			}
			body, _ := json.Marshal(raw)
			return json.Marshal(hostAuthGetResponse{AuthIndex: name, Name: name, Path: "/auths/" + name, JSON: body})
		case pluginabi.MethodHostAuthSave:
			var request struct {
				Name string          `json:"name"`
				JSON json.RawMessage `json:"json"`
			}
			if err := json.Unmarshal(payload, &request); err != nil {
				return nil, err
			}
			updated := map[string]any{}
			if err := json.Unmarshal(request.JSON, &updated); err != nil {
				return nil, err
			}
			auths[request.Name] = updated
			return json.Marshal(pluginapi.HostAuthSaveResponse{Name: request.Name, Path: "/auths/" + request.Name})
		default:
			return nil, fmt.Errorf("unexpected host callback %s", method)
		}
	}
	t.Cleanup(func() {
		hostCall = originalHostCall
		invalidateAuthListCache()
		invalidateAuthProxyCache()
	})
}

func managementStatus(t *testing.T, raw []byte) int {
	t.Helper()
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	var response managementResponse
	if err := json.Unmarshal(env.Result, &response); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode
}

func TestDisablingNodeReconcilesAccountsAndPreservesDisabledState(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	source, err := store.createNode("source", "http://127.0.0.1:7961", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	target, err := store.createNode("target", "http://127.0.0.1:7962", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	auths := map[string]map[string]any{
		"active.json": {
			"type": "xai", "access_token": "active-token", "proxy_url": source.ProxyURL, "disabled": false,
		},
		"manual.json": {
			"type": "xai", "access_token": "manual-token", "proxy_url": source.ProxyURL,
			"disabled": true, "disabled_reason": "operator maintenance", "custom": "keep",
		},
	}
	installAuthFixture(t, auths)

	body, _ := json.Marshal(map[string]any{"enabled": false})
	response, err := dispatchAPI(http.MethodPatch, "/nodes/"+source.ID, nil, body)
	if err != nil {
		t.Fatal(err)
	}
	if got := managementStatus(t, response); got != http.StatusOK {
		t.Fatalf("disable status=%d, want %d", got, http.StatusOK)
	}
	if node, _ := store.getNode(source.ID); node.Enabled {
		t.Fatal("source node remains enabled")
	}
	if got := auths["active.json"]["proxy_url"]; got != target.ProxyURL {
		t.Fatalf("active account proxy=%q, want %q", got, target.ProxyURL)
	}
	if got := auths["manual.json"]["proxy_url"]; got != target.ProxyURL {
		t.Fatalf("disabled account proxy=%q, want %q", got, target.ProxyURL)
	}
	if disabled, _ := auths["manual.json"]["disabled"].(bool); !disabled {
		t.Fatal("disabled account was re-enabled")
	}
	if reason := auths["manual.json"]["disabled_reason"]; reason != "operator maintenance" {
		t.Fatalf("disabled reason=%q, want preserved reason", reason)
	}
	if custom := auths["manual.json"]["custom"]; custom != "keep" {
		t.Fatalf("custom auth field=%q, want preserved field", custom)
	}

	// Repeating an explicit disable is idempotent and must not rebind accounts
	// back to the disabled source node.
	response, err = dispatchAPI(http.MethodPatch, "/nodes/"+source.ID, nil, body)
	if err != nil || managementStatus(t, response) != http.StatusOK {
		t.Fatalf("repeated disable failed: err=%v status=%d", err, managementStatus(t, response))
	}
}

func TestBatchDisablingNodesDoesNotMigrateIntoBatch(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	first, err := store.createNode("first", "http://127.0.0.1:7971", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.createNode("second", "http://127.0.0.1:7972", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	target, err := store.createNode("target", "http://127.0.0.1:7973", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	auths := map[string]map[string]any{
		"first.json":  {"type": "xai", "access_token": "first-token", "proxy_url": first.ProxyURL, "disabled": false},
		"second.json": {"type": "xai", "access_token": "second-token", "proxy_url": second.ProxyURL, "disabled": false},
	}
	installAuthFixture(t, auths)

	body, _ := json.Marshal(map[string]any{"ids": []string{first.ID, second.ID}, "enabled": false})
	response, err := dispatchAPI(http.MethodPatch, "/nodes/batch", nil, body)
	if err != nil {
		t.Fatal(err)
	}
	if got := managementStatus(t, response); got != http.StatusOK {
		t.Fatalf("batch disable status=%d, want %d", got, http.StatusOK)
	}
	if got := auths["first.json"]["proxy_url"]; got != target.ProxyURL {
		t.Fatalf("first account proxy=%q, want %q", got, target.ProxyURL)
	}
	if got := auths["second.json"]["proxy_url"]; got != target.ProxyURL {
		t.Fatalf("second account proxy=%q, want %q", got, target.ProxyURL)
	}
}

func TestDisablingLastNodeUnbindsAccounts(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	source, err := store.createNode("source", "http://127.0.0.1:7981", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	auths := map[string]map[string]any{
		"active.json": {
			"type": "xai", "access_token": "active-token", "proxy_url": source.ProxyURL, "disabled": false,
		},
		"disabled.json": {
			"type": "xai", "access_token": "disabled-token", "proxy_url": source.ProxyURL, "disabled": true,
		},
	}
	installAuthFixture(t, auths)

	body, _ := json.Marshal(map[string]any{"enabled": false})
	response, err := dispatchAPI(http.MethodPatch, "/nodes/"+source.ID, nil, body)
	if err != nil || managementStatus(t, response) != http.StatusOK {
		t.Fatalf("disable last node failed: err=%v status=%d", err, managementStatus(t, response))
	}
	for name, raw := range auths {
		if _, ok := raw["proxy_url"]; ok {
			t.Errorf("%s remains bound: %v", name, raw["proxy_url"])
		}
	}
	if disabled, _ := auths["disabled.json"]["disabled"].(bool); !disabled {
		t.Fatal("disabled account was re-enabled while unbinding")
	}
}

func TestDisabledNodeBorrowsOnlyRandomNormalAccounts(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	auths := map[string]map[string]any{
		"normal-a.json": {"type": "xai", "access_token": "a-token", "proxy_url": "http://127.0.0.1:7991", "disabled": false},
		"normal-b.json": {"type": "xai", "access_token": "b-token", "proxy_url": "http://127.0.0.1:7992", "disabled": false},
		"disabled.json": {"type": "xai", "access_token": "disabled-token", "proxy_url": "http://127.0.0.1:7993", "disabled": true},
		"expired.json":  {"type": "xai", "access_token": "expired-token", "proxy_url": "http://127.0.0.1:7994", "disabled": false, "expired": time.Now().Add(-time.Hour).Format(time.RFC3339)},
		"empty.json":    {"type": "xai", "access_token": "", "proxy_url": "http://127.0.0.1:7995", "disabled": false},
	}
	installAuthFixture(t, auths)

	candidates, err := listAuthsForNode(&nodeRecord{ProxyURL: "http://127.0.0.1:7999", Enabled: false}, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 {
		t.Fatalf("candidate count=%d, want 2", len(candidates))
	}
	for _, candidate := range candidates {
		if candidate.Name != "normal-a.json" && candidate.Name != "normal-b.json" {
			t.Fatalf("unexpected borrowed candidate %q", candidate.Name)
		}
	}
	for name, raw := range auths {
		if name == "normal-a.json" || name == "normal-b.json" {
			continue
		}
		if raw["proxy_url"] == nil {
			t.Fatalf("fixture proxy unexpectedly changed for %s", name)
		}
	}
}

func TestNoNormalAccountReturnsNoAccountError(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	auths := map[string]map[string]any{
		"disabled.json": {"type": "xai", "access_token": "disabled-token", "disabled": true},
		"expired.json":  {"type": "xai", "access_token": "expired-token", "disabled": false, "expired": time.Now().Add(-time.Hour).Format(time.RFC3339)},
		"empty.json":    {"type": "xai", "access_token": "", "disabled": false},
	}
	installAuthFixture(t, auths)

	_, err := listAuthsForNode(&nodeRecord{ProxyURL: "http://127.0.0.1:8001", Enabled: false}, 1)
	if err == nil || err.Error() != "没有可用的 CPA xAI 账号" {
		t.Fatalf("error=%v, want no-account error", err)
	}
}
