package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Account actions configurable per threshold tier.
const (
	accountActionDisable = "disable"
	accountActionDelete  = "delete"
	accountActionNone    = "none"
)

// Tiers that can trigger an action.
const (
	tierSoft = "soft"
	tierHard = "hard"
	tierFail = "fail"
)

// Persisted action markers on an account record.
const (
	actedDisabled = "disabled"
	actedDeleted  = "deleted"
)

type policyConfig struct {
	SoftTPS         float64 `json:"soft_tps"`
	HardTPS         float64 `json:"hard_tps"`
	ConsecutiveSoft int     `json:"consecutive_soft"`
	ConsecutiveFail int     `json:"consecutive_fail"`
	SoftAction      string  `json:"soft_action"`
	HardAction      string  `json:"hard_action"`
	FailAction      string  `json:"fail_action"`
	MinKeepAccounts int     `json:"min_keep_accounts"`
	DryRun          bool    `json:"dry_run"`
}

type accountRecord struct {
	Key                string  `json:"key"`
	Name               string  `json:"name,omitempty"`
	Email              string  `json:"email,omitempty"`
	Index              string  `json:"index,omitempty"`
	SoftStrikes        int     `json:"soft_strikes"`
	FailStrikes        int     `json:"fail_strikes"`
	LastClassification string  `json:"last_classification,omitempty"`
	LastOutputTPS      float64 `json:"last_output_tps,omitempty"`
	LastOutputTokens   int64   `json:"last_output_tokens,omitempty"`
	LastDurationMs     int64   `json:"last_duration_ms,omitempty"`
	LastFirstTokenMs   int64   `json:"last_first_token_ms,omitempty"`
	LastObservedAt     float64 `json:"last_observed_at,omitempty"`
	ObservedCount      int64   `json:"observed_count"`
	Action             string  `json:"action,omitempty"`
	ActedAt            float64 `json:"acted_at,omitempty"`
	Reason             string  `json:"reason,omitempty"`
}

type guardEvent struct {
	TS             float64 `json:"ts"`
	Event          string  `json:"event"`
	AccountKey     string  `json:"account_key,omitempty"`
	AccountName    string  `json:"account_name,omitempty"`
	Email          string  `json:"email,omitempty"`
	Tier           string  `json:"tier,omitempty"`
	Action         string  `json:"action,omitempty"`
	Classification string  `json:"classification,omitempty"`
	OutputTPS      float64 `json:"output_tps,omitempty"`
	Reason         string  `json:"reason,omitempty"`
	DryRun         bool    `json:"dry_run,omitempty"`
}

type observationStats struct {
	Total        int64 `json:"total"`
	Healthy      int64 `json:"healthy"`
	Soft         int64 `json:"soft"`
	Hard         int64 `json:"hard"`
	Failed       int64 `json:"failed"`
	Unmapped     int64 `json:"unmapped"`
	OutputTokens int64 `json:"output_tokens"`
}

type actionStats struct {
	Disabled   int64 `json:"disabled"`
	Deleted    int64 `json:"deleted"`
	Suppressed int64 `json:"suppressed"`
	DryRun     int64 `json:"dry_run"`
}

type statistics struct {
	StartedAt    float64          `json:"started_at"`
	Observations observationStats `json:"observations"`
	Actions      actionStats      `json:"actions"`
}

type guardState struct {
	Version   int                       `json:"version"`
	Policy    policyConfig              `json:"policy"`
	Accounts  map[string]*accountRecord `json:"accounts"`
	Events    []guardEvent              `json:"events"`
	Stats     statistics                `json:"statistics"`
	UpdatedAt float64                   `json:"updated_at"`
}

type stateStore struct {
	mu   sync.Mutex
	path string
	data guardState
}

func defaultPolicy() policyConfig {
	return policyConfig{
		SoftTPS:         500,
		HardTPS:         1000,
		ConsecutiveSoft: 2,
		ConsecutiveFail: 3,
		SoftAction:      accountActionDisable,
		HardAction:      accountActionDelete,
		FailAction:      accountActionDisable,
		MinKeepAccounts: 2,
		DryRun:          false,
	}
}

func normalizeAccountAction(v string) string {
	switch strings.TrimSpace(v) {
	case accountActionDisable, accountActionDelete, accountActionNone:
		return strings.TrimSpace(v)
	default:
		return ""
	}
}

func newStateStore(path string) *stateStore {
	s := &stateStore{path: path}
	s.data = guardState{
		Version:  1,
		Policy:   defaultPolicy(),
		Accounts: map[string]*accountRecord{},
		Stats:    statistics{StartedAt: float64(time.Now().Unix())},
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
	if data.Accounts == nil {
		data.Accounts = map[string]*accountRecord{}
	}
	if data.Policy.HardTPS <= 0 || data.Policy.SoftTPS <= 0 {
		data.Policy = defaultPolicy()
	}
	if normalizeAccountAction(data.Policy.SoftAction) == "" {
		data.Policy.SoftAction = accountActionDisable
	}
	if normalizeAccountAction(data.Policy.HardAction) == "" {
		data.Policy.HardAction = accountActionDelete
	}
	if normalizeAccountAction(data.Policy.FailAction) == "" {
		data.Policy.FailAction = accountActionDisable
	}
	if data.Policy.ConsecutiveSoft <= 0 {
		data.Policy.ConsecutiveSoft = 2
	}
	if data.Policy.ConsecutiveFail <= 0 {
		data.Policy.ConsecutiveFail = 3
	}
	if data.Policy.MinKeepAccounts < 0 {
		data.Policy.MinKeepAccounts = 0
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
	if out.Accounts == nil {
		out.Accounts = map[string]*accountRecord{}
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
	softAction := normalizeAccountAction(p.SoftAction)
	if softAction == "" {
		return fmt.Errorf("软阈值动作无效")
	}
	hardAction := normalizeAccountAction(p.HardAction)
	if hardAction == "" {
		return fmt.Errorf("硬阈值动作无效")
	}
	failAction := normalizeAccountAction(p.FailAction)
	if failAction == "" {
		return fmt.Errorf("连续失败动作无效")
	}
	p.SoftAction = softAction
	p.HardAction = hardAction
	p.FailAction = failAction
	if p.ConsecutiveSoft <= 0 {
		p.ConsecutiveSoft = 2
	}
	if p.ConsecutiveFail <= 0 {
		p.ConsecutiveFail = 3
	}
	if p.MinKeepAccounts < 0 {
		p.MinKeepAccounts = 0
	}
	s.data.Policy = p
	return s.persistLocked()
}

// accountKey is the persistent identity for an account: file name first, auth
// index as fallback. Mirrors the egress plugin's cooldown key so the same
// account maps to the same record across restarts.
func accountKey(a authFile) string {
	if name := filepath.Base(strings.TrimSpace(a.Name)); name != "" && name != "." {
		return "name:" + name
	}
	if idx := strings.TrimSpace(a.Index); idx != "" {
		return "index:" + idx
	}
	return ""
}

// upsertAccount applies mut to the record for a, creating it on first sight.
// Returns a copy of the stored record.
func (s *stateStore) upsertAccount(a authFile, mut func(*accountRecord)) (*accountRecord, error) {
	key := accountKey(a)
	if key == "" {
		return nil, fmt.Errorf("账号缺少可持久化标识")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Accounts == nil {
		s.data.Accounts = map[string]*accountRecord{}
	}
	rec, ok := s.data.Accounts[key]
	if !ok {
		rec = &accountRecord{Key: key}
		s.data.Accounts[key] = rec
	}
	if name := strings.TrimSpace(a.Name); name != "" {
		rec.Name = name
	}
	if email := strings.TrimSpace(a.Email); email != "" {
		rec.Email = email
	}
	if idx := strings.TrimSpace(a.Index); idx != "" {
		rec.Index = idx
	}
	if mut != nil {
		mut(rec)
	}
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	cp := *rec
	return &cp, nil
}

func (s *stateStore) getAccount(key string) (*accountRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.data.Accounts[key]
	if !ok {
		return nil, false
	}
	cp := *rec
	return &cp, true
}

func (s *stateStore) listAccounts() []*accountRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*accountRecord, 0, len(s.data.Accounts))
	for _, rec := range s.data.Accounts {
		cp := *rec
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
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

func (s *stateStore) bumpStat(class string, tokens int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	obs := &s.data.Stats.Observations
	obs.Total++
	obs.OutputTokens += tokens
	switch class {
	case "healthy":
		obs.Healthy++
	case tierSoft:
		obs.Soft++
	case tierHard:
		obs.Hard++
	case "failed":
		obs.Failed++
	}
	_ = s.persistLocked()
}

func (s *stateStore) bumpUnmapped() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Stats.Observations.Unmapped++
	_ = s.persistLocked()
}

func (s *stateStore) bumpAction(kind string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch kind {
	case "disabled":
		s.data.Stats.Actions.Disabled++
	case "deleted":
		s.data.Stats.Actions.Deleted++
	case "suppressed":
		s.data.Stats.Actions.Suppressed++
	case "dry_run":
		s.data.Stats.Actions.DryRun++
	}
	_ = s.persistLocked()
}
