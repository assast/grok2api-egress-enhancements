package main

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// fakeHost stubs the host-facing seams so guard logic can run without CPA.
type fakeHost struct {
	auth       authFile
	enabled    int
	enabledErr error
	disabled   []string
	deleted    []string
	found      bool
}

func newFakeHost(t *testing.T, name string, enabled int) *fakeHost {
	t.Helper()
	h := &fakeHost{
		auth:    authFile{Name: name, Index: "0", Email: "user@example.com"},
		enabled: enabled,
		found:   true,
	}
	origLookup, origEnabled, origDisable, origDelete := lookupAccount, enabledAccounts, disableAccount, deleteAccount
	t.Cleanup(func() {
		lookupAccount, enabledAccounts, disableAccount, deleteAccount = origLookup, origEnabled, origDisable, origDelete
	})
	lookupAccount = func(usageObservation) (authFile, bool) { return h.auth, h.found }
	enabledAccounts = func() (int, error) { return h.enabled, h.enabledErr }
	disableAccount = func(a authFile, reason string) error {
		h.disabled = append(h.disabled, a.Name)
		h.auth.Disabled = true
		return nil
	}
	deleteAccount = func(a authFile, reason string) error {
		h.deleted = append(h.deleted, a.Name)
		h.found = false
		return nil
	}
	return h
}

func newTestStore(t *testing.T, mut func(*policyConfig)) *stateStore {
	t.Helper()
	s := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	p := s.policy()
	if mut != nil {
		mut(&p)
	}
	if err := s.updatePolicy(p); err != nil {
		t.Fatalf("updatePolicy: %v", err)
	}
	return s
}

func usageRecord(outTokens, durMs, ttftMs int64, failed bool) map[string]any {
	return map[string]any{
		"AuthID":         "xai-test.json",
		"output_tokens":  float64(outTokens),
		"duration_ms":    float64(durMs),
		"first_token_ms": float64(ttftMs),
		"failed":         failed,
	}
}

func countEvents(s *stateStore, name string) int {
	n := 0
	for _, e := range s.events() {
		if e.Event == name {
			n++
		}
	}
	return n
}

// --- 7.1 判定与计数 ---

func TestComputeTPSUsesGenerationWindow(t *testing.T) {
	// 1050 tokens over a 500ms generation window (1100-600) => ~2100 TPS
	if got := computeTPS(1050, 1100, 600); got < 2099 || got > 2101 {
		t.Fatalf("computeTPS()=%v, want ~2100", got)
	}
	// tiny generation window falls back to full duration (avoid false hard)
	if got := computeTPS(100, 1000, 950); got < 99 || got > 101 {
		t.Fatalf("computeTPS()=%v, want ~100 with min window fallback", got)
	}
	if got := computeTPS(100, 0, 0); got != 0 {
		t.Fatalf("computeTPS()=%v, want 0", got)
	}
	// duration below the minimum generation window yields no signal
	if got := computeTPS(100, 50, 0); got != 0 {
		t.Fatalf("computeTPS()=%v, want 0 for sub-window duration", got)
	}
}

func TestClassifyTPS(t *testing.T) {
	if classifyTPS(1200, 500, 1000) != tierHard {
		t.Fatal("expected hard")
	}
	if classifyTPS(1000, 500, 1000) != tierHard {
		t.Fatal("hard threshold must be inclusive")
	}
	if classifyTPS(600, 500, 1000) != tierSoft {
		t.Fatal("expected soft")
	}
	if classifyTPS(100, 500, 1000) != "healthy" {
		t.Fatal("expected healthy")
	}
	if classifyTPS(0, 500, 1000) != "unknown" {
		t.Fatal("expected unknown")
	}
}

func TestSmallOutputNeverTriggersHard(t *testing.T) {
	pol := defaultPolicy()
	pol.SoftTPS = 50
	pol.HardTPS = 100
	// 31 tokens over a 200ms window => 155 TPS, but the output is tiny.
	class, tps := classifyObservation(pol, usageObservation{OutputTokens: 31, DurationMs: 200})
	if class != "healthy" || tps != 0 {
		t.Fatalf("small output classified as %q tps=%v, want healthy/0", class, tps)
	}
	// 40 tokens over the same window stays hard.
	if class, _ := classifyObservation(pol, usageObservation{OutputTokens: 40, DurationMs: 200}); class != tierHard {
		t.Fatalf("class = %q, want hard above the small-output guard", class)
	}
}

func TestSoftStrikesTriggerAfterConsecutiveAndResetOnHealthy(t *testing.T) {
	s := newTestStore(t, func(p *policyConfig) {
		p.ConsecutiveSoft = 2
		p.SoftAction = accountActionDisable
		p.MinKeepAccounts = 0
	})
	h := newFakeHost(t, "xai-test.json", 5)

	handleAccountUsage(s, usageRecord(600, 1000, 0, false)) // soft #1
	if len(h.disabled) != 0 {
		t.Fatalf("single soft observation must not act, disabled=%v", h.disabled)
	}
	handleAccountUsage(s, usageRecord(100, 1000, 0, false)) // healthy resets
	rec, _ := s.getAccount("name:xai-test.json")
	if rec == nil || rec.SoftStrikes != 0 {
		t.Fatalf("healthy observation must reset soft strikes: %#v", rec)
	}
	handleAccountUsage(s, usageRecord(600, 1000, 0, false)) // soft #1 again
	if len(h.disabled) != 0 {
		t.Fatalf("soft counter must restart after healthy, disabled=%v", h.disabled)
	}
	handleAccountUsage(s, usageRecord(600, 1000, 0, false)) // soft #2 -> act
	if len(h.disabled) != 1 {
		t.Fatalf("consecutive soft must disable once, disabled=%v", h.disabled)
	}
	if countEvents(s, "account_disabled") != 1 {
		t.Fatalf("expected one account_disabled event, events=%#v", s.events())
	}
}

func TestHardTriggersImmediately(t *testing.T) {
	s := newTestStore(t, func(p *policyConfig) {
		p.HardAction = accountActionDelete
		p.MinKeepAccounts = 0
	})
	h := newFakeHost(t, "xai-test.json", 5)

	handleAccountUsage(s, usageRecord(1200, 1000, 0, false)) // 1200 TPS >= hard
	if len(h.deleted) != 1 {
		t.Fatalf("hard threshold must act on the first hit, deleted=%v", h.deleted)
	}
	rec, _ := s.getAccount("name:xai-test.json")
	if rec == nil || rec.Action != actedDeleted {
		t.Fatalf("account must be marked deleted: %#v", rec)
	}
}

func TestFailStrikesTriggerAndResetOnSuccess(t *testing.T) {
	s := newTestStore(t, func(p *policyConfig) {
		p.ConsecutiveFail = 3
		p.FailAction = accountActionDisable
		p.MinKeepAccounts = 0
	})
	h := newFakeHost(t, "xai-test.json", 5)

	handleAccountUsage(s, usageRecord(0, 0, 0, true))
	handleAccountUsage(s, usageRecord(0, 0, 0, true))
	if len(h.disabled) != 0 {
		t.Fatalf("two failures must not act, disabled=%v", h.disabled)
	}
	handleAccountUsage(s, usageRecord(100, 1000, 0, false)) // success resets
	rec, _ := s.getAccount("name:xai-test.json")
	if rec == nil || rec.FailStrikes != 0 {
		t.Fatalf("non-failed observation must reset fail strikes: %#v", rec)
	}
	for i := 0; i < 3; i++ {
		handleAccountUsage(s, usageRecord(0, 0, 0, true))
	}
	if len(h.disabled) != 1 {
		t.Fatalf("three consecutive failures must disable once, disabled=%v", h.disabled)
	}
}

func TestUnmappedUsageNeverActs(t *testing.T) {
	s := newTestStore(t, func(p *policyConfig) { p.MinKeepAccounts = 0 })
	h := newFakeHost(t, "xai-test.json", 5)
	h.found = false

	handleAccountUsage(s, usageRecord(5000, 1000, 0, false)) // would be hard
	if len(h.disabled) != 0 || len(h.deleted) != 0 {
		t.Fatalf("unmapped usage must not act: disabled=%v deleted=%v", h.disabled, h.deleted)
	}
	if countEvents(s, "usage_unmapped") != 1 {
		t.Fatalf("expected usage_unmapped event, events=%#v", s.events())
	}
	if s.stats().Observations.Unmapped != 1 {
		t.Fatalf("unmapped statistic not recorded: %#v", s.stats().Observations)
	}
}

// --- 7.2 安全阀 / dry-run / 幂等 ---

func TestMinKeepAccountsSuppressesAction(t *testing.T) {
	s := newTestStore(t, func(p *policyConfig) {
		p.HardAction = accountActionDelete
		p.MinKeepAccounts = 2
	})
	h := newFakeHost(t, "xai-test.json", 2) // 2-1 = 1 < 2 -> suppress

	handleAccountUsage(s, usageRecord(1200, 1000, 0, false))
	if len(h.deleted) != 0 {
		t.Fatalf("action must be suppressed below min_keep_accounts, deleted=%v", h.deleted)
	}
	if countEvents(s, "action_suppressed") != 1 {
		t.Fatalf("expected action_suppressed event, events=%#v", s.events())
	}
	if s.stats().Actions.Suppressed != 1 {
		t.Fatalf("suppressed statistic not recorded: %#v", s.stats().Actions)
	}

	h.enabled = 3 // 3-1 = 2 >= 2 -> act
	handleAccountUsage(s, usageRecord(1200, 1000, 0, false))
	if len(h.deleted) != 1 {
		t.Fatalf("action must run above min_keep_accounts, deleted=%v", h.deleted)
	}
}

func TestMinKeepAccountsSuppressesWhenCountUnavailable(t *testing.T) {
	s := newTestStore(t, func(p *policyConfig) {
		p.HardAction = accountActionDelete
		p.MinKeepAccounts = 1
	})
	h := newFakeHost(t, "xai-test.json", 0)
	h.enabledErr = http.ErrServerClosed

	handleAccountUsage(s, usageRecord(1200, 1000, 0, false))
	if len(h.deleted) != 0 {
		t.Fatalf("unknown pool size must suppress irreversible action, deleted=%v", h.deleted)
	}
	if countEvents(s, "action_suppressed") != 1 {
		t.Fatalf("expected action_suppressed event, events=%#v", s.events())
	}
}

func TestDryRunRecordsWithoutActing(t *testing.T) {
	s := newTestStore(t, func(p *policyConfig) {
		p.HardAction = accountActionDelete
		p.MinKeepAccounts = 0
		p.DryRun = true
	})
	h := newFakeHost(t, "xai-test.json", 5)

	handleAccountUsage(s, usageRecord(1200, 1000, 0, false))
	if len(h.deleted) != 0 || len(h.disabled) != 0 {
		t.Fatalf("dry run must not act: disabled=%v deleted=%v", h.disabled, h.deleted)
	}
	if countEvents(s, "dry_run_would_act") != 1 {
		t.Fatalf("expected dry_run_would_act event, events=%#v", s.events())
	}
	rec, _ := s.getAccount("name:xai-test.json")
	if rec == nil || rec.Action != "" {
		t.Fatalf("dry run must not mark the account acted: %#v", rec)
	}
}

func TestActionIsIdempotentAndClearedOnManualRecovery(t *testing.T) {
	s := newTestStore(t, func(p *policyConfig) {
		p.ConsecutiveSoft = 1
		p.SoftAction = accountActionDisable
		p.MinKeepAccounts = 0
	})
	h := newFakeHost(t, "xai-test.json", 5)

	handleAccountUsage(s, usageRecord(600, 1000, 0, false))
	if len(h.disabled) != 1 {
		t.Fatalf("first soft trip must disable, disabled=%v", h.disabled)
	}
	// Still disabled: a late usage event must not repeat the action.
	handleAccountUsage(s, usageRecord(600, 1000, 0, false))
	if len(h.disabled) != 1 {
		t.Fatalf("action must not repeat on an already-acted account, disabled=%v", h.disabled)
	}

	// Operator re-enables the account in the CPA panel.
	h.auth.Disabled = false
	handleAccountUsage(s, usageRecord(600, 1000, 0, false))
	if countEvents(s, "account_action_cleared") != 1 {
		t.Fatalf("expected account_action_cleared event, events=%#v", s.events())
	}
	if len(h.disabled) != 2 {
		t.Fatalf("restored account must be actionable again, disabled=%v", h.disabled)
	}
}

func TestNoneActionRecordsWithoutActing(t *testing.T) {
	s := newTestStore(t, func(p *policyConfig) {
		p.HardAction = accountActionNone
		p.MinKeepAccounts = 2
	})
	h := newFakeHost(t, "xai-test.json", 1) // below min_keep, but none never acts

	handleAccountUsage(s, usageRecord(1200, 1000, 0, false))
	if len(h.deleted) != 0 || len(h.disabled) != 0 {
		t.Fatalf("none action must not touch the account")
	}
	if countEvents(s, "action_none") != 1 {
		t.Fatalf("expected action_none event, events=%#v", s.events())
	}
}

// --- 7.3 策略校验 ---

func TestDefaultPolicy(t *testing.T) {
	p := defaultPolicy()
	if p.SoftTPS != 500 || p.HardTPS != 1000 {
		t.Fatalf("thresholds = %v/%v, want 500/1000", p.SoftTPS, p.HardTPS)
	}
	if p.ConsecutiveSoft != 2 || p.ConsecutiveFail != 3 {
		t.Fatalf("counters = %d/%d, want 2/3", p.ConsecutiveSoft, p.ConsecutiveFail)
	}
	if p.SoftAction != accountActionDisable || p.HardAction != accountActionDelete || p.FailAction != accountActionDisable {
		t.Fatalf("actions = %q/%q/%q", p.SoftAction, p.HardAction, p.FailAction)
	}
	if p.MinKeepAccounts != 2 || p.DryRun {
		t.Fatalf("min_keep=%d dry_run=%v, want 2/false", p.MinKeepAccounts, p.DryRun)
	}
}

func TestUpdatePolicyValidation(t *testing.T) {
	s := newStateStore(filepath.Join(t.TempDir(), "state.json"))

	bad := s.policy()
	bad.SoftTPS = 1000
	bad.HardTPS = 1000
	if err := s.updatePolicy(bad); err == nil {
		t.Fatal("soft >= hard must be rejected")
	}
	bad = s.policy()
	bad.SoftTPS = 0
	if err := s.updatePolicy(bad); err == nil {
		t.Fatal("non-positive soft threshold must be rejected")
	}
	for _, field := range []string{"soft", "hard", "fail"} {
		bad = s.policy()
		switch field {
		case "soft":
			bad.SoftAction = "quarantine"
		case "hard":
			bad.HardAction = "quarantine"
		case "fail":
			bad.FailAction = "quarantine"
		}
		if err := s.updatePolicy(bad); err == nil {
			t.Fatalf("invalid %s action must be rejected", field)
		}
	}
	if s.policy().SoftTPS != 500 || s.policy().HardTPS != 1000 {
		t.Fatalf("rejected updates must leave the policy untouched: %#v", s.policy())
	}

	good := s.policy()
	good.SoftTPS = 300
	good.HardTPS = 900
	good.HardAction = accountActionDisable
	good.ConsecutiveSoft = 0 // normalized back to the default
	if err := s.updatePolicy(good); err != nil {
		t.Fatal(err)
	}
	got := s.policy()
	if got.SoftTPS != 300 || got.HardTPS != 900 || got.HardAction != accountActionDisable || got.ConsecutiveSoft != 2 {
		t.Fatalf("policy not applied: %#v", got)
	}
}

func TestPolicySurvivesReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s := newStateStore(path)
	p := s.policy()
	p.SoftAction = accountActionNone
	p.DryRun = true
	if err := s.updatePolicy(p); err != nil {
		t.Fatal(err)
	}
	reloaded := newStateStore(path).policy()
	if reloaded.SoftAction != accountActionNone || !reloaded.DryRun {
		t.Fatalf("policy did not survive restart: %#v", reloaded)
	}
}

// --- 状态与路由 ---

func TestAccountKeyPrefersName(t *testing.T) {
	if got := accountKey(authFile{Name: "xai-a@b.com.json", Index: "3"}); got != "name:xai-a@b.com.json" {
		t.Fatalf("got %q", got)
	}
	if got := accountKey(authFile{Index: "3"}); got != "index:3" {
		t.Fatalf("got %q", got)
	}
	if got := accountKey(authFile{}); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestEventRingBufferCapsAt100(t *testing.T) {
	s := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	for i := 0; i < 120; i++ {
		s.appendEvent(guardEvent{Event: "account_disabled", Reason: string(rune('a' + i%26))})
	}
	if got := len(s.events()); got != 100 {
		t.Fatalf("events = %d, want 100", got)
	}
}

func TestExtractUsageFieldsAcceptsHostVariants(t *testing.T) {
	obs := extractUsageFields(map[string]any{
		"AuthID":  "xai-a.json",
		"Detail":  map[string]any{"OutputTokens": float64(200), "ReasoningTokens": float64(50)},
		"Latency": 1.5e9, // nanoseconds
		"TTFT":    3e8,
		"Failed":  false,
	})
	if obs.OutputTokens != 250 {
		t.Fatalf("output tokens = %d, want 250", obs.OutputTokens)
	}
	if obs.DurationMs != 1500 || obs.FirstTokenMs != 300 {
		t.Fatalf("duration=%d ttft=%d, want 1500/300", obs.DurationMs, obs.FirstTokenMs)
	}
	if obs.AuthID != "xai-a.json" {
		t.Fatalf("auth id = %q", obs.AuthID)
	}
}

func TestUIProxyRejectsMissingHeader(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "s.json"))
	body, _ := json.Marshal(uiProxyRequest{Method: http.MethodGet, Path: "/policy"})
	raw, err := handleUIProxy(managementRequest{Method: http.MethodPost, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"StatusCode":403`) {
		t.Fatalf("got %s", raw)
	}
}

func TestDispatchPolicyRoundTrip(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "s.json"))
	headers := make(http.Header)
	headers.Set(managementUIHeader, "1")

	update, _ := json.Marshal(map[string]any{"softTPS": 200, "hard_tps": 800, "hardAction": "disable", "dry_run": true})
	body, _ := json.Marshal(uiProxyRequest{Method: http.MethodPut, Path: "/policy", Body: update})
	raw, err := handleUIProxy(managementRequest{Method: http.MethodPost, Headers: headers, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if resp := decodeManagement(t, raw); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d body %s", resp.StatusCode, resp.Body)
	}
	got := store.policy()
	if got.SoftTPS != 200 || got.HardTPS != 800 || got.HardAction != accountActionDisable || !got.DryRun {
		t.Fatalf("policy not updated through the API: %#v", got)
	}

	bad, _ := json.Marshal(map[string]any{"soft_tps": 900, "hard_tps": 800})
	body, _ = json.Marshal(uiProxyRequest{Method: http.MethodPut, Path: "/policy", Body: bad})
	raw, err = handleUIProxy(managementRequest{Method: http.MethodPost, Headers: headers, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if resp := decodeManagement(t, raw); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid policy must be rejected, got %d %s", resp.StatusCode, resp.Body)
	}
	if store.policy().SoftTPS != 200 {
		t.Fatalf("rejected update must not change the policy: %#v", store.policy())
	}
}

func decodeManagement(t *testing.T, raw []byte) managementResponse {
	t.Helper()
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	var resp managementResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestRenderStatusPage(t *testing.T) {
	page := strings.Replace(pageTemplate, "/*__HALLMARK_TOKENS__*/", tokenCSS, 1)
	for _, want := range []string{
		"账号守护",
		"X-Grok2API-Account-Guard-UI",
		"policy-soft-action",
		"policy-hard-action",
		"policy-fail-action",
		"policy-min-keep",
		"policy-dry-run",
		"观测模式",
		"最低保留账号数",
		"/v0/management/grok2api-account-guard/api",
		// quality probe controls
		"data-quality=",
		"batch-quality",
		"select-all",
		"/accounts/quality-test",
		"policy-probe-model",
		"policy-probe-tokens",
		// event stream additions
		"account_observed",
		"events-actions-only",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Contains(page, "/*__HALLMARK_TOKENS__*/") {
		t.Fatal("tokens not replaced")
	}
	// The egress plugin's API surface must not leak into this UI.
	for _, unwanted := range []string{"grok2api-egress", "X-Grok2API-Egress-UI"} {
		if strings.Contains(page, unwanted) {
			t.Fatalf("unexpected egress identifier %q in account-guard page", unwanted)
		}
	}
}

// --- 主动质量探测 ---

func stubProbe(t *testing.T, res probeResult) {
	t.Helper()
	orig := probeAccountQualityFn
	t.Cleanup(func() { probeAccountQualityFn = orig })
	probeAccountQualityFn = func(policyConfig, authFile) probeResult { return res }
}

func stubAuthList(t *testing.T, auths ...authFile) {
	t.Helper()
	orig := listAllAuths
	t.Cleanup(func() { listAllAuths = orig })
	listAllAuths = func() ([]authFile, error) { return auths, nil }
}

func TestRunQualityProbesResolvesKeysAndActs(t *testing.T) {
	s := newTestStore(t, func(p *policyConfig) {
		p.HardAction = accountActionDelete
		p.MinKeepAccounts = 0
	})
	h := newFakeHost(t, "xai-test.json", 5)
	stubAuthList(t, h.auth)
	stubProbe(t, probeResult{Classification: tierHard, TPS: 1240, OutputTokens: 400, DurationMs: 322})

	results, err := runQualityProbes(s, []string{"name:xai-test.json", "name:missing.json"})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	if results[0].Classification != tierHard || results[0].Name != "xai-test.json" {
		t.Fatalf("unexpected probe result: %#v", results[0])
	}
	if results[1].Error == "" {
		t.Fatalf("unknown key must report an error: %#v", results[1])
	}
	if len(h.deleted) != 1 {
		t.Fatalf("hard probe result must trigger the policy, deleted=%v", h.deleted)
	}
}
func TestProbeObservationFeedsGuard(t *testing.T) {
	s := newTestStore(t, func(p *policyConfig) {
		p.HardAction = accountActionDelete
		p.MinKeepAccounts = 0
	})
	h := newFakeHost(t, "xai-test.json", 5)

	applyObservation(s, h.auth, observation{
		Classification: tierHard,
		TPS:            1240,
		OutputTokens:   400,
		DurationMs:     322,
		Source:         sourceProbe,
	})
	if len(h.deleted) != 1 {
		t.Fatalf("probe hard result must act like a passive one, deleted=%v", h.deleted)
	}
	rec, _ := s.getAccount("name:xai-test.json")
	if rec == nil || rec.LastSource != sourceProbe {
		t.Fatalf("probe source not recorded: %#v", rec)
	}
	found := false
	for _, e := range s.events() {
		if e.Event == "account_deleted" && e.Source == sourceProbe {
			found = true
		}
	}
	if !found {
		t.Fatalf("action event must carry the probe source, events=%#v", s.events())
	}
}

func TestProbeErrorCountsAsFailure(t *testing.T) {
	s := newTestStore(t, func(p *policyConfig) {
		p.ConsecutiveFail = 2
		p.FailAction = accountActionDisable
		p.MinKeepAccounts = 0
	})
	h := newFakeHost(t, "xai-test.json", 5)

	for i := 0; i < 2; i++ {
		applyObservation(s, h.auth, observation{
			Classification: "failed",
			Failed:         true,
			Source:         sourceProbe,
			Detail:         "主动探测失败: 上游 HTTP 401",
		})
	}
	if len(h.disabled) != 1 {
		t.Fatalf("two failed probes must disable, disabled=%v", h.disabled)
	}
}

func TestProbeClassifiesAndGuardsSmallOutput(t *testing.T) {
	pol := defaultPolicy()
	pol.SoftTPS = 50
	pol.HardTPS = 100
	// The probe applies the same small-output guard as the passive path.
	if got := classifyTPS(computeTPS(31, 200, 0), pol.SoftTPS, pol.HardTPS); got != tierHard {
		t.Fatalf("precondition: raw classification = %q, want hard", got)
	}
	class, tps := classifyObservation(pol, usageObservation{OutputTokens: 31, DurationMs: 200})
	if class != "healthy" || tps != 0 {
		t.Fatalf("small output must be downgraded, got %q/%v", class, tps)
	}
}

func TestProbeDefaultsInPolicy(t *testing.T) {
	p := defaultPolicy()
	if p.ProbeModel != defaultProbeModel || p.ProbeMaxTokens != defaultProbeMaxTokens {
		t.Fatalf("probe defaults = %q/%d", p.ProbeModel, p.ProbeMaxTokens)
	}
	s := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	bad := s.policy()
	bad.ProbeModel = "   "
	bad.ProbeMaxTokens = -1
	if err := s.updatePolicy(bad); err != nil {
		t.Fatal(err)
	}
	got := s.policy()
	if got.ProbeModel != defaultProbeModel || got.ProbeMaxTokens != defaultProbeMaxTokens {
		t.Fatalf("blank probe settings must fall back to defaults: %#v", got)
	}
}

// --- 观测事件流 ---

func TestEveryObservationEmitsAnEvent(t *testing.T) {
	s := newTestStore(t, func(p *policyConfig) { p.MinKeepAccounts = 0 })
	newFakeHost(t, "xai-test.json", 5)

	handleAccountUsage(s, usageRecord(100, 1000, 0, false)) // healthy — the 307 Token/s case
	events := s.events()
	if len(events) != 1 {
		t.Fatalf("healthy observation must be recorded, events=%#v", events)
	}
	ev := events[0]
	if ev.Event != "account_observed" || ev.Classification != "healthy" || ev.Source != sourcePassive {
		t.Fatalf("unexpected observation event: %#v", ev)
	}
	if ev.AccountName != "xai-test.json" || ev.OutputTPS != 100 {
		t.Fatalf("observation event missing detail: %#v", ev)
	}
}

func TestSoftObservationEventShowsStrikeProgress(t *testing.T) {
	s := newTestStore(t, func(p *policyConfig) {
		p.ConsecutiveSoft = 3
		p.MinKeepAccounts = 0
	})
	newFakeHost(t, "xai-test.json", 5)

	handleAccountUsage(s, usageRecord(600, 1000, 0, false))
	events := s.events()
	last := events[len(events)-1]
	if last.Classification != tierSoft {
		t.Fatalf("expected soft observation, got %#v", last)
	}
	if !strings.Contains(last.Reason, "1/3") {
		t.Fatalf("soft observation must show strike progress, reason=%q", last.Reason)
	}
}
