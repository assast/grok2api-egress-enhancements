package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	http429AccountActionDelete     = "delete_account"
	http429AccountActionCooldown24 = "cooldown_24h"
)

type policyConfig struct {
	Mode                 string  `json:"mode"`
	ActiveIntervalSec    int     `json:"active_interval_seconds"`
	PassivePollSec       int     `json:"passive_poll_seconds"`
	QuarantineSec        int     `json:"quarantine_seconds"`
	SoftTPS              float64 `json:"soft_tps"`
	HardTPS              float64 `json:"hard_tps"`
	ConsecutiveSoft      int     `json:"consecutive_soft"`
	ConsecutiveErrors    int     `json:"consecutive_errors"`
	MinHealthyNodes      int     `json:"min_healthy_nodes"`
	Model                string  `json:"model"`
	DisableAuthOnHard    bool    `json:"disable_auth_on_hard"`
	MaxOutputTokensProbe int     `json:"max_output_tokens"`
	HTTP429AccountAction string  `json:"http_429_account_action"`
}

type accountCooldown struct {
	Until float64 `json:"until"`
}

type nodeRecord struct {
	ID                   string    `json:"id"`
	Name                 string    `json:"name"`
	ProxyURL             string    `json:"-"` // never serialize to API clients in clear form via dedicated DTO
	ProxyURLStored       string    `json:"proxy_url"`
	Enabled              bool      `json:"enabled"`
	ProxyPool            bool      `json:"proxy_pool"`
	AccountCapacity      int       `json:"account_capacity"`
	ExitIP               string    `json:"exit_ip,omitempty"`
	ProbeStatus          string    `json:"probe_status,omitempty"`
	ProbeLatencyMs       int64     `json:"probe_latency_ms,omitempty"`
	AssignedAccountCount int       `json:"assigned_account_count"`
	DisabledByGuard      bool      `json:"disabled_by_guard"`
	QuarantinedUntil     float64   `json:"quarantined_until,omitempty"`
	ErrorStrikes         int       `json:"error_strikes"`
	SoftStrikes          int       `json:"soft_strikes"`
	LastClassification   string    `json:"last_classification,omitempty"`
	LastOutputTPS        float64   `json:"last_output_tps,omitempty"`
	LastFirstTokenMs     int64     `json:"last_first_token_ms,omitempty"`
	LastDurationMs       int64     `json:"last_duration_ms,omitempty"`
	LastOutputTokens     int64     `json:"last_output_tokens,omitempty"`
	LastReason           string    `json:"last_reason,omitempty"`
	LastSource           string    `json:"last_source,omitempty"`
	LastObservedAt       float64   `json:"last_observed_at,omitempty"`
	LastProbeAt          float64   `json:"last_probe_at,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

type guardEvent struct {
	TS             float64 `json:"ts"`
	Event          string  `json:"event"`
	NodeID         string  `json:"node_id,omitempty"`
	NodeName       string  `json:"node_name,omitempty"`
	AuthID         string  `json:"auth_id,omitempty"`
	Reason         string  `json:"reason,omitempty"`
	Classification string  `json:"classification,omitempty"`
	OutputTPS      float64 `json:"output_tps,omitempty"`
}

type probeStats struct {
	Total        int64 `json:"total"`
	Healthy      int64 `json:"healthy"`
	Soft         int64 `json:"soft"`
	Hard         int64 `json:"hard"`
	Errors       int64 `json:"errors"`
	OutputTokens int64 `json:"output_tokens"`
}

type actionStats struct {
	Quarantined int64 `json:"quarantined"`
	Restored    int64 `json:"restored"`
	Suppressed  int64 `json:"suppressed"`
}

type statistics struct {
	StartedAt float64     `json:"started_at"`
	Active    probeStats  `json:"active"`
	Passive   probeStats  `json:"passive"`
	Actions   actionStats `json:"actions"`
}

type guardState struct {
	Version          int                        `json:"version"`
	Policy           policyConfig               `json:"policy"`
	Nodes            map[string]*nodeRecord     `json:"nodes"`
	Events           []guardEvent               `json:"events"`
	Stats            statistics                 `json:"statistics"`
	AccountCooldowns map[string]accountCooldown `json:"account_cooldowns,omitempty"`
	NextID           int                        `json:"next_id"`
	UpdatedAt        float64                    `json:"updated_at"`
}

type stateStore struct {
	mu   sync.Mutex
	path string
	data guardState
}

func defaultPolicy() policyConfig {
	return policyConfig{
		Mode:                 "hybrid",
		ActiveIntervalSec:    1800,
		PassivePollSec:       5,
		QuarantineSec:        120,
		SoftTPS:              500,
		HardTPS:              1000,
		ConsecutiveSoft:      2,
		ConsecutiveErrors:    2,
		MinHealthyNodes:      1,
		Model:                "grok-4.5",
		DisableAuthOnHard:    true,
		MaxOutputTokensProbe: 384,
		HTTP429AccountAction: http429AccountActionCooldown24,
	}
}

func newStateStore(path string) *stateStore {
	s := &stateStore{path: path}
	s.data = guardState{
		Version:          1,
		Policy:           defaultPolicy(),
		Nodes:            map[string]*nodeRecord{},
		Events:           nil,
		Stats:            statistics{StartedAt: float64(time.Now().Unix())},
		AccountCooldowns: map[string]accountCooldown{},
		NextID:           1,
	}
	_ = s.load()
	return s
}

func (s *stateStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return s.persistLocked()
		}
		return err
	}
	var data guardState
	if err := json.Unmarshal(raw, &data); err != nil {
		return err
	}
	if data.Nodes == nil {
		data.Nodes = map[string]*nodeRecord{}
	}
	if data.AccountCooldowns == nil {
		data.AccountCooldowns = map[string]accountCooldown{}
	}
	if data.NextID <= 0 {
		data.NextID = 1
	}
	if data.Policy.HardTPS <= 0 {
		data.Policy = defaultPolicy()
	}
	if data.Policy.HTTP429AccountAction == "" {
		data.Policy.HTTP429AccountAction = http429AccountActionDelete
	}
	// hydrate private proxy field
	for _, n := range data.Nodes {
		n.ProxyURL = n.ProxyURLStored
	}
	s.data = data
	return nil
}

// persistLocked writes state; caller MUST hold s.mu.
func (s *stateStore) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	s.data.UpdatedAt = float64(time.Now().Unix())
	for _, n := range s.data.Nodes {
		n.ProxyURLStored = n.ProxyURL
	}
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *stateStore) snapshot() guardState {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, _ := json.Marshal(s.data)
	var out guardState
	_ = json.Unmarshal(raw, &out)
	if out.Nodes == nil {
		out.Nodes = map[string]*nodeRecord{}
	}
	for id, n := range s.data.Nodes {
		if out.Nodes[id] != nil {
			out.Nodes[id].ProxyURL = n.ProxyURL
		}
	}
	return out
}

func (s *stateStore) policy() policyConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Policy
}

func (s *stateStore) updatePolicy(p policyConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.SoftTPS <= 0 || p.HardTPS <= 0 || p.SoftTPS >= p.HardTPS {
		return fmt.Errorf("软阈值必须低于硬阈值且都大于 0")
	}
	if p.Mode == "" {
		p.Mode = "hybrid"
	}
	if p.Model == "" {
		p.Model = "grok-4.5"
	}
	if p.ConsecutiveSoft <= 0 {
		p.ConsecutiveSoft = 2
	}
	if p.ConsecutiveErrors <= 0 {
		p.ConsecutiveErrors = 2
	}
	if p.QuarantineSec <= 0 {
		p.QuarantineSec = 120
	}
	if p.MinHealthyNodes <= 0 {
		p.MinHealthyNodes = 1
	}
	if p.HTTP429AccountAction == "" {
		p.HTTP429AccountAction = http429AccountActionDelete
	}
	if p.HTTP429AccountAction != http429AccountActionDelete && p.HTTP429AccountAction != http429AccountActionCooldown24 {
		return fmt.Errorf("429 账号处理策略无效")
	}
	s.data.Policy = p
	return s.persistLocked()
}

func accountCooldownKey(a authFile) string {
	if name := filepath.Base(strings.TrimSpace(a.Name)); name != "" && name != "." {
		return "name:" + name
	}
	return "index:" + strings.TrimSpace(a.Index)
}

func (s *stateStore) isAccountCooling(a authFile, now time.Time) bool {
	key := accountCooldownKey(a)
	if key == "index:" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cooldown, ok := s.data.AccountCooldowns[key]
	if !ok || cooldown.Until <= float64(now.Unix()) {
		if ok {
			delete(s.data.AccountCooldowns, key)
			_ = s.persistLocked()
		}
		return false
	}
	return true
}

func (s *stateStore) coolAccountFor(a authFile, duration time.Duration) (time.Time, error) {
	key := accountCooldownKey(a)
	if key == "index:" {
		return time.Time{}, fmt.Errorf("账号缺少可持久化标识")
	}
	until := time.Now().Add(duration).UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.AccountCooldowns == nil {
		s.data.AccountCooldowns = map[string]accountCooldown{}
	}
	s.data.AccountCooldowns[key] = accountCooldown{Until: float64(until.Unix())}
	return until, s.persistLocked()
}

func (s *stateStore) listNodes() []*nodeRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*nodeRecord, 0, len(s.data.Nodes))
	for _, n := range s.data.Nodes {
		cp := *n
		cp.ProxyURL = n.ProxyURL
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})
	return out
}

func (s *stateStore) getNode(id string) (*nodeRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.data.Nodes[id]
	if !ok {
		return nil, false
	}
	cp := *n
	cp.ProxyURL = n.ProxyURL
	return &cp, true
}

func (s *stateStore) createNode(name, proxyURL string, enabled, pool bool, capacity int) (*nodeRecord, error) {
	items, err := s.createNodes(name, []string{proxyURL}, enabled, pool, capacity)
	if err != nil {
		return nil, err
	}
	return items[0], nil
}

// createNodes creates one node per proxy URL. A single URL keeps baseName as-is;
// multiple URLs append a zero-padded suffix (name-01, name-02, ...).
func (s *stateStore) createNodes(baseName string, proxyURLs []string, enabled, pool bool, capacity int) ([]*nodeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	baseName = strings.TrimSpace(baseName)
	proxies := uniqueNonEmpty(proxyURLs)
	if baseName == "" || len(proxies) == 0 {
		return nil, fmt.Errorf("名称和代理 URL 必填")
	}
	now := time.Now().UTC()
	width := len(fmt.Sprintf("%d", len(proxies)))
	if width < 2 {
		width = 2
	}
	out := make([]*nodeRecord, 0, len(proxies))
	for i, proxyURL := range proxies {
		name := baseName
		if len(proxies) > 1 {
			name = fmt.Sprintf("%s-%0*d", baseName, width, i+1)
		}
		id := fmt.Sprintf("%d", s.data.NextID)
		s.data.NextID++
		n := &nodeRecord{
			ID:              id,
			Name:            name,
			ProxyURL:        proxyURL,
			ProxyURLStored:  proxyURL,
			Enabled:         enabled,
			ProxyPool:       pool,
			AccountCapacity: capacity,
			ProbeStatus:     "unknown",
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		s.data.Nodes[id] = n
		cp := *n
		out = append(out, &cp)
	}
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return out, nil
}

func uniqueNonEmpty(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

type exitIPDedupGroup struct {
	ExitIP    string   `json:"exit_ip"`
	KeepID    string   `json:"keep_id"`
	DeleteIDs []string `json:"delete_ids"`
}

func nodeIDLess(left, right string) bool {
	leftNumber, leftErr := strconv.ParseUint(left, 10, 64)
	rightNumber, rightErr := strconv.ParseUint(right, 10, 64)
	if leftErr == nil && rightErr == nil {
		return leftNumber < rightNumber
	}
	return left < right
}

func planExitIPDedup(nodes []*nodeRecord) []exitIPDedupGroup {
	byExitIP := map[string][]*nodeRecord{}
	for _, node := range nodes {
		if node == nil || strings.TrimSpace(node.ExitIP) == "" {
			continue
		}
		ip := strings.TrimSpace(node.ExitIP)
		byExitIP[ip] = append(byExitIP[ip], node)
	}
	groups := make([]exitIPDedupGroup, 0)
	for exitIP, groupNodes := range byExitIP {
		if len(groupNodes) < 2 {
			continue
		}
		sort.Slice(groupNodes, func(i, j int) bool { return nodeIDLess(groupNodes[i].ID, groupNodes[j].ID) })
		deleteIDs := make([]string, 0, len(groupNodes)-1)
		for _, node := range groupNodes[1:] {
			deleteIDs = append(deleteIDs, node.ID)
		}
		groups = append(groups, exitIPDedupGroup{ExitIP: exitIP, KeepID: groupNodes[0].ID, DeleteIDs: deleteIDs})
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].ExitIP < groups[j].ExitIP })
	return groups
}

func (s *stateStore) updateNode(id string, mut func(*nodeRecord) error) (*nodeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.data.Nodes[id]
	if !ok {
		return nil, fmt.Errorf("节点不存在")
	}
	if err := mut(n); err != nil {
		return nil, err
	}
	n.UpdatedAt = time.Now().UTC()
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	cp := *n
	cp.ProxyURL = n.ProxyURL
	return &cp, nil
}

func (s *stateStore) deleteNodes(ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		delete(s.data.Nodes, id)
	}
	return s.persistLocked()
}

func (s *stateStore) setBatchEnabled(ids []string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		if n, ok := s.data.Nodes[id]; ok {
			n.Enabled = enabled
			n.UpdatedAt = time.Now().UTC()
		}
	}
	return s.persistLocked()
}

func (s *stateStore) appendEvent(ev guardEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ev.TS == 0 {
		ev.TS = float64(time.Now().Unix())
	}
	s.data.Events = append(s.data.Events, ev)
	if len(s.data.Events) > 100 {
		s.data.Events = s.data.Events[len(s.data.Events)-100:]
	}
	_ = s.persistLocked()
}

func (s *stateStore) events() []guardEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]guardEvent, len(s.data.Events))
	copy(out, s.data.Events)
	return out
}

func (s *stateStore) stats() statistics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Stats
}

func (s *stateStore) bumpStat(source, class string, tokens int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ps *probeStats
	if source == "active" {
		ps = &s.data.Stats.Active
	} else {
		ps = &s.data.Stats.Passive
	}
	ps.Total++
	ps.OutputTokens += tokens
	switch class {
	case "healthy":
		ps.Healthy++
	case "soft":
		ps.Soft++
	case "hard":
		ps.Hard++
	case "error":
		ps.Errors++
	}
	_ = s.persistLocked()
}

func (s *stateStore) bumpAction(kind string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch kind {
	case "quarantined":
		s.data.Stats.Actions.Quarantined++
	case "restored":
		s.data.Stats.Actions.Restored++
	case "suppressed":
		s.data.Stats.Actions.Suppressed++
	}
	_ = s.persistLocked()
}

func (s *stateStore) setAssignedCounts(counts map[string]int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, n := range s.data.Nodes {
		n.AssignedAccountCount = counts[id]
	}
	_ = s.persistLocked()
}

func publicNode(n *nodeRecord) map[string]any {
	if n == nil {
		return nil
	}
	return map[string]any{
		"id":                   n.ID,
		"name":                 n.Name,
		"enabled":              n.Enabled,
		"proxyPool":            n.ProxyPool,
		"accountCapacity":      n.AccountCapacity,
		"exitIp":               n.ExitIP,
		"probeStatus":          n.ProbeStatus,
		"probeLatencyMs":       n.ProbeLatencyMs,
		"assignedAccountCount": n.AssignedAccountCount,
		"disabled_by_guard":    n.DisabledByGuard,
		"quarantined_until":    n.QuarantinedUntil,
		"error_strikes":        n.ErrorStrikes,
		"soft_strikes":         n.SoftStrikes,
		"last_classification":  n.LastClassification,
		"last_output_tps":      n.LastOutputTPS,
		"last_first_token_ms":  n.LastFirstTokenMs,
		"last_duration_ms":     n.LastDurationMs,
		"last_output_tokens":   n.LastOutputTokens,
		"last_reason":          n.LastReason,
		"last_source":          n.LastSource,
		"last_observed_at":     n.LastObservedAt,
		"last_probe_at":        n.LastProbeAt,
		"hasProxy":             n.ProxyURL != "",
		"createdAt":            n.CreatedAt,
		"updatedAt":            n.UpdatedAt,
	}
}
