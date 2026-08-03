package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestComputeTPSUsesGenerationWindow(t *testing.T) {
	// 1050 tokens over 500ms generation window (1100-600) => 2100 TPS
	if got := computeTPS(1050, 1100, 600); got < 2099 || got > 2101 {
		t.Fatalf("computeTPS()=%v, want ~2100", got)
	}
	// tiny generation window falls back to full duration (avoid false hard)
	// 100 tokens / 1000ms => 100 TPS
	if got := computeTPS(100, 1000, 950); got < 99 || got > 101 {
		t.Fatalf("computeTPS()=%v, want ~100 with min window fallback", got)
	}
	if got := computeTPS(100, 0, 0); got != 0 {
		t.Fatalf("computeTPS()=%v, want 0", got)
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

func TestHTTP429AccountActionDefaultsToCooldown(t *testing.T) {
	if got := defaultPolicy().HTTP429AccountAction; got != http429AccountActionCooldown24 {
		t.Fatalf("default HTTP 429 action = %q, want %q", got, http429AccountActionCooldown24)
	}
	if !isAccountRateLimited(http.StatusTooManyRequests) {
		t.Fatal("HTTP 429 must use the account handling policy")
	}
	if isAccountRateLimited(http.StatusBadGateway) {
		t.Fatal("non-429 response must not use the account handling policy")
	}
}


func TestNon429IsolationActionDefaultsAndValidation(t *testing.T) {
	if got := defaultPolicy().Non429IsolationAction; got != non429IsolationIsolateOnly {
		t.Fatalf("default non429 action = %q, want %q", got, non429IsolationIsolateOnly)
	}
	s := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	p := s.policy()
	p.Non429IsolationAction = "not-a-real-action"
	if err := s.updatePolicy(p); err == nil {
		t.Fatal("invalid non429 action must be rejected")
	}
	p = s.policy()
	p.Non429IsolationAction = non429IsolationDeleteOnly
	if err := s.updatePolicy(p); err != nil {
		t.Fatal(err)
	}
	if s.policy().Non429IsolationAction != non429IsolationDeleteOnly {
		t.Fatalf("got %q", s.policy().Non429IsolationAction)
	}
}

func TestNon429IsolationActionLegacyLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	// Old state without non_429_isolation_action, with disable_auth_on_hard noise
	raw := `{
  "version": 1,
  "policy": {
    "mode": "hybrid",
    "soft_tps": 500,
    "hard_tps": 1000,
    "disable_auth_on_hard": true,
    "http_429_account_action": "cooldown_24h"
  },
  "nodes": {},
  "next_id": 1
}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newStateStore(path)
	if got := s.policy().Non429IsolationAction; got != non429IsolationIsolateOnly {
		t.Fatalf("legacy load Non429IsolationAction = %q, want isolate_only", got)
	}
}

func TestDeleteAccountOnlyDoesNotQuarantine(t *testing.T) {
	s := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	p := s.policy()
	p.Non429IsolationAction = non429IsolationDeleteOnly
	p.MinHealthyNodes = 1
	if err := s.updatePolicy(p); err != nil {
		t.Fatal(err)
	}
	// two nodes so isolate path would also be allowed; we assert delete_only never isolates
	n1, err := s.createNode("a", "http://127.0.0.1:1", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.createNode("b", "http://127.0.0.1:2", true, false, 0); err != nil {
		t.Fatal(err)
	}
	res := qualityResult{
		Classification: "hard",
		TPS:            2000,
		OutputTokens:   100,
		DurationMs:     50,
		HitAuth:        authFile{Name: "xai-hit.json"},
		HasHit:         false, // no real file → skip delete, still must not quarantine
	}
	applyObservation(s, n1.ID, "active", res)
	updated, ok := s.getNode(n1.ID)
	if !ok || updated.DisabledByGuard {
		t.Fatalf("delete_account_only must not quarantine node: %#v", updated)
	}
	evs := s.events()
	foundSkip := false
	for _, e := range evs {
		if e.Event == "account_delete_skipped" {
			foundSkip = true
		}
		if e.Event == "node_quarantined" {
			t.Fatalf("unexpected quarantine event: %#v", e)
		}
	}
	if !foundSkip {
		t.Fatal("expected account_delete_skipped when no hit auth")
	}
}

func TestIsolateOnlyQuarantinesOnHard(t *testing.T) {
	s := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	p := s.policy()
	p.Non429IsolationAction = non429IsolationIsolateOnly
	p.MinHealthyNodes = 1
	if err := s.updatePolicy(p); err != nil {
		t.Fatal(err)
	}
	n1, err := s.createNode("a", "http://127.0.0.1:1", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.createNode("b", "http://127.0.0.1:2", true, false, 0); err != nil {
		t.Fatal(err)
	}
	res := qualityResult{
		Classification: "hard",
		TPS:            2000,
		OutputTokens:   100,
		DurationMs:     50,
		HitAuth:        authFile{Name: "xai-hit.json"},
		HasHit:         true,
	}
	applyObservation(s, n1.ID, "active", res)
	updated, ok := s.getNode(n1.ID)
	if !ok || !updated.DisabledByGuard {
		t.Fatalf("isolate_only must quarantine on hard: %#v", updated)
	}
	found := false
	for _, e := range s.events() {
		if e.Event == "node_quarantined" && e.AuthID == "xai-hit.json" {
			found = true
		}
	}
	if !found {
		t.Fatalf("quarantine event must include hit auth, events=%#v", s.events())
	}
}

func TestExitIPDedupPlanKeepsSmallestNodeID(t *testing.T) {
	nodes := []*nodeRecord{
		{ID: "12", Name: "later", ExitIP: "203.0.113.9"},
		{ID: "2", Name: "first", ExitIP: "203.0.113.9"},
		{ID: "7", Name: "unique", ExitIP: "203.0.113.10"},
		{ID: "9", Name: "unknown"},
	}
	groups := planExitIPDedup(nodes)
	if len(groups) != 1 {
		t.Fatalf("groups = %#v, want one duplicate group", groups)
	}
	if groups[0].ExitIP != "203.0.113.9" || groups[0].KeepID != "2" || len(groups[0].DeleteIDs) != 1 || groups[0].DeleteIDs[0] != "12" {
		t.Fatalf("unexpected dedup plan %#v", groups[0])
	}
}

func TestAccountCooldownSurvivesReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s := newStateStore(path)
	auth := authFile{Name: "xai-limited.json"}
	if _, err := s.coolAccountFor(auth, time.Hour); err != nil {
		t.Fatal(err)
	}
	if !s.isAccountCooling(auth, time.Now()) {
		t.Fatal("account must be skipped while its 429 cooldown is active")
	}
	if !newStateStore(path).isAccountCooling(auth, time.Now()) {
		t.Fatal("account cooldown must survive plugin restart")
	}
}

func TestAccountLimitedResultDoesNotAffectNodeQuality(t *testing.T) {
	s := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	node, err := s.createNode("channel", "http://127.0.0.1:1", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	applyObservation(s, node.ID, "active", qualityResult{Classification: "account_limited", Error: "账号已冷却", HitAuth: authFile{Name: "xai-limited.json"}, HasHit: true})
	updated, ok := s.getNode(node.ID)
	if !ok || updated.ErrorStrikes != 0 || updated.DisabledByGuard {
		t.Fatalf("429 account handling changed node state: %#v", updated)
	}
	stats := s.stats()
	if stats.Active.Total != 1 || stats.Active.Errors != 0 {
		t.Fatalf("unexpected active statistics: %#v", stats.Active)
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

func TestCreateNodesBatch(t *testing.T) {
	s := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	items, err := s.createNodes("pool", []string{
		"socks5h://u:p@1.example:1080",
		"",
		"socks5h://u:p@2.example:1080",
		"socks5h://u:p@1.example:1080", // duplicate ignored
		"socks5h://u:p@3.example:1080",
	}, true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("len=%d want 3", len(items))
	}
	if items[0].Name != "pool-01" || items[1].Name != "pool-02" || items[2].Name != "pool-03" {
		t.Fatalf("names %#v", []string{items[0].Name, items[1].Name, items[2].Name})
	}
	if items[0].ProxyURL != "socks5h://u:p@1.example:1080" {
		t.Fatalf("proxy %q", items[0].ProxyURL)
	}
}

func TestCollectProxyURLs(t *testing.T) {
	got := collectProxyURLs(map[string]any{
		"proxyURL":  "socks5h://a\n\nsocks5h://b\r\nsocks5h://a",
		"proxyURLs": []any{"socks5h://c", "  socks5h://b  "},
	})
	want := []string{"socks5h://c", "socks5h://b", "socks5h://a"}
	// uniqueNonEmpty preserves first-seen: proxyURLs first, then proxyURL lines
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestRenderStatusPage(t *testing.T) {
	page := strings.Replace(pageTemplate, "/*__HALLMARK_TOKENS__*/", tokenCSS, 1)
	for _, want := range []string{"出口守护", "纯 CPA", "data-batch=\"enable\"", "重平衡账号", "剔重出口 IP", "policy-429-account-action", "policy-non429-isolation-action", "non429IsolationAction", "X-Grok2API-Egress-UI", "一行一个", "proxyURLs"} {
		if !strings.Contains(page, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Contains(page, "/*__HALLMARK_TOKENS__*/") {
		t.Fatal("tokens not replaced in test helper path only")
	}
	if !strings.Contains(page, "minHealthyNodes:Number($('policy-min-healthy').value),http429AccountAction") {
		t.Fatal("policy save script must close the min healthy node Number call before the 429 action")
	}
	if !strings.Contains(page, "non429IsolationAction:$('policy-non429-isolation-action').value") {
		t.Fatal("policy save script must include non429IsolationAction")
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
