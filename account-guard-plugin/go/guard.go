package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// Host-facing operations are indirected so the guard logic can be unit tested
// without a live CPA host.
var (
	lookupAccount   = resolveUsageAccount
	enabledAccounts = countEnabledAccounts
	disableAccount  = func(a authFile, reason string) error {
		// Keep the existing proxy binding; this plugin never touches egress.
		return setAuthProxyAndFlags(a, a.ProxyURL, true, reason)
	}
	deleteAccount = deleteAuthFile
)

func computeTPS(outputTokens, durationMs, firstTokenMs int64) float64 {
	if outputTokens <= 0 || durationMs <= 0 {
		return 0
	}
	denom := durationMs - firstTokenMs
	// Short replies often have firstToken ≈ duration, which blows up TPS and
	// false-triggers hard actions. Require a minimum generation window.
	const minGenMs int64 = 200
	if denom < minGenMs {
		denom = durationMs
	}
	if denom < minGenMs {
		return 0
	}
	return float64(outputTokens) / (float64(denom) / 1000.0)
}

// classifyTPS grades output throughput: higher Token/s means worse quality
// (a degraded upstream answers fast with low-value tokens).
func classifyTPS(tps float64, soft, hard float64) string {
	if tps <= 0 {
		return "unknown"
	}
	if tps >= hard {
		return tierHard
	}
	if tps >= soft {
		return tierSoft
	}
	return "healthy"
}

func anyInt(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	case int:
		return int64(t)
	case json.Number:
		i, _ := t.Int64()
		return i
	default:
		return 0
	}
}

type usageObservation struct {
	AuthID       string
	AuthIndex    string
	Failed       bool
	OutputTokens int64
	DurationMs   int64
	FirstTokenMs int64
}

// extractUsageFields reads a CPA usage record. Field names differ across host
// versions, so every known spelling is probed.
func extractUsageFields(record map[string]any) usageObservation {
	obs := usageObservation{
		AuthID:    firstString(record, "AuthID", "auth_id", "authId", "AuthIndex", "auth_index"),
		AuthIndex: firstString(record, "AuthIndex", "auth_index"),
	}
	if v, ok := record["Failed"]; ok {
		obs.Failed, _ = v.(bool)
	}
	if v, ok := record["failed"]; ok {
		obs.Failed, _ = v.(bool)
	}

	if detail, ok := record["Detail"].(map[string]any); ok {
		obs.OutputTokens = anyInt(detail["OutputTokens"]) + anyInt(detail["ReasoningTokens"])
	}
	if detail, ok := record["detail"].(map[string]any); ok {
		if obs.OutputTokens == 0 {
			obs.OutputTokens = anyInt(detail["output_tokens"]) + anyInt(detail["reasoning_tokens"]) + anyInt(detail["OutputTokens"])
		}
	}
	if obs.OutputTokens == 0 {
		obs.OutputTokens = firstInt(record, "output_tokens", "OutputTokens", "completion_tokens")
	}

	obs.DurationMs = firstInt(record, "duration_ms", "DurationMs", "latency_ms")
	if obs.DurationMs == 0 {
		if lat, ok := record["Latency"].(float64); ok {
			// encoding/json decodes time.Duration as nanoseconds
			obs.DurationMs = durationFieldToMs(lat)
		}
		if lat, ok := record["latency"].(float64); ok && obs.DurationMs == 0 {
			obs.DurationMs = durationFieldToMs(lat)
		}
	}

	obs.FirstTokenMs = firstInt(record, "first_token_ms", "FirstTokenMs", "ttft_ms")
	if obs.FirstTokenMs == 0 {
		if t, ok := record["TTFT"].(float64); ok {
			obs.FirstTokenMs = durationFieldToMs(t)
		}
	}
	return obs
}

func durationFieldToMs(value float64) int64 {
	if value > 1e6 {
		return int64(value / 1e6)
	}
	return int64(value)
}

// resolveUsageAccount locates the account file a usage record belongs to.
func resolveUsageAccount(obs usageObservation) (authFile, bool) {
	keys := []string{obs.AuthID, obs.AuthIndex}
	if obs.AuthID != "" {
		base := filepath.Base(obs.AuthID)
		keys = append(keys, base, strings.TrimSuffix(base, ".json"))
	}
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" || key == "." {
			continue
		}
		if a, err := getAuthFile(key); err == nil {
			return a, true
		}
	}
	return authFile{}, false
}

// classifyObservation grades one usage event for an account.
func classifyObservation(pol policyConfig, obs usageObservation) (string, float64) {
	if obs.Failed {
		return "failed", 0
	}
	tps := computeTPS(obs.OutputTokens, obs.DurationMs, obs.FirstTokenMs)
	class := classifyTPS(tps, pol.SoftTPS, pol.HardTPS)
	// Very small outputs must never trigger the irreversible hard action.
	if class == tierHard && obs.OutputTokens < 32 {
		return "healthy", 0
	}
	return class, tps
}

func actionForTier(pol policyConfig, tier string) string {
	switch tier {
	case tierSoft:
		return normalizeAccountAction(pol.SoftAction)
	case tierHard:
		return normalizeAccountAction(pol.HardAction)
	case tierFail:
		return normalizeAccountAction(pol.FailAction)
	default:
		return ""
	}
}

// handleAccountUsage is the whole passive pipeline: locate the account,
// classify the call, update strikes, and act when a tier trips.
func handleAccountUsage(store *stateStore, record map[string]any) {
	pol := store.policy()
	obs := extractUsageFields(record)

	auth, ok := lookupAccount(obs)
	if !ok {
		store.bumpUnmapped()
		store.appendEvent(guardEvent{
			Event:  "usage_unmapped",
			Reason: fmt.Sprintf("usage 无法定位账号 auth=%s idx=%s", obs.AuthID, obs.AuthIndex),
		})
		return
	}

	class, tps := classifyObservation(pol, obs)
	now := float64(time.Now().Unix())
	var (
		tier    string
		cleared bool
	)
	rec, err := store.upsertAccount(auth, func(r *accountRecord) {
		// 人工恢复：账号被改回启用（或被重新添加）→ 清除历史动作标记，允许再次触发。
		if r.Action != "" && !auth.Disabled {
			r.Action = ""
			r.ActedAt = 0
			r.Reason = ""
			cleared = true
		}
		r.LastClassification = class
		r.LastOutputTPS = tps
		r.LastOutputTokens = obs.OutputTokens
		r.LastDurationMs = obs.DurationMs
		r.LastFirstTokenMs = obs.FirstTokenMs
		r.LastObservedAt = now
		r.ObservedCount++
		// 任意一次非失败观测清零失败计数。
		if !obs.Failed {
			r.FailStrikes = 0
		}
		switch class {
		case "healthy":
			r.SoftStrikes = 0
		case tierSoft:
			r.SoftStrikes++
			if r.SoftStrikes >= pol.ConsecutiveSoft {
				tier = tierSoft
			}
		case tierHard:
			tier = tierHard
		case "failed":
			r.FailStrikes++
			if r.FailStrikes >= pol.ConsecutiveFail {
				tier = tierFail
			}
		}
	})
	store.bumpStat(class, obs.OutputTokens)
	if err != nil || rec == nil {
		return
	}
	if cleared {
		store.appendEvent(guardEvent{
			Event:       "account_action_cleared",
			AccountKey:  rec.Key,
			AccountName: rec.Name,
			Email:       rec.Email,
			Reason:      "账号已恢复启用，清除历史动作标记",
		})
	}
	if tier == "" {
		return
	}

	var reason string
	switch tier {
	case tierSoft:
		reason = fmt.Sprintf("连续 %d 次软阈值降智 Token/s=%.1f", rec.SoftStrikes, tps)
	case tierHard:
		reason = fmt.Sprintf("硬阈值降智 Token/s=%.1f", tps)
	case tierFail:
		reason = fmt.Sprintf("连续 %d 次调用失败", rec.FailStrikes)
	}
	applyAccountAction(store, tier, auth, rec, reason, class, tps)
}

// applyAccountAction runs the configured action for a tripped tier:
// safety valve → dry run → idempotency → execute.
func applyAccountAction(store *stateStore, tier string, auth authFile, rec *accountRecord, reason, class string, tps float64) {
	pol := store.policy()
	action := actionForTier(pol, tier)
	if action == "" {
		action = accountActionNone
	}
	base := guardEvent{
		AccountKey:     rec.Key,
		AccountName:    rec.Name,
		Email:          rec.Email,
		Tier:           tier,
		Action:         action,
		Classification: class,
		OutputTPS:      tps,
	}
	emit := func(name, why string, dryRun bool) {
		ev := base
		ev.Event = name
		ev.Reason = why
		ev.DryRun = dryRun
		store.appendEvent(ev)
	}

	if action == accountActionNone {
		emit("action_none", "策略为不处理: "+reason, false)
		return
	}

	// 安全阀：执行后启用账号数不得低于 min_keep_accounts。
	if pol.MinKeepAccounts > 0 {
		enabled, err := enabledAccounts()
		if err != nil {
			// 无法确认账号池规模时不执行动作，避免删空。
			store.bumpAction("suppressed")
			emit("action_suppressed", "无法统计启用账号数: "+err.Error(), false)
			return
		}
		if enabled-1 < pol.MinKeepAccounts {
			store.bumpAction("suppressed")
			emit("action_suppressed", fmt.Sprintf("低于最低保留账号数（当前启用 %d，最低 %d）: %s", enabled, pol.MinKeepAccounts, reason), false)
			return
		}
	}

	if pol.DryRun {
		store.bumpAction("dry_run")
		emit("dry_run_would_act", reason, true)
		return
	}

	// 幂等：已执行过动作的账号不重复处理。
	if rec.Action != "" {
		return
	}

	actedReason := "account-guard " + tierLabel(tier) + ": " + reason
	switch action {
	case accountActionDisable:
		if err := disableAccount(auth, actedReason); err != nil {
			emit("account_disable_failed", "停用账号失败: "+err.Error(), false)
			return
		}
		markAccountActed(store, auth, actedDisabled, reason)
		store.bumpAction("disabled")
		emit("account_disabled", reason, false)
	case accountActionDelete:
		if err := deleteAccount(auth, actedReason); err != nil {
			emit("account_delete_skipped", "删除账号失败: "+err.Error(), false)
			return
		}
		markAccountActed(store, auth, actedDeleted, reason)
		store.bumpAction("deleted")
		emit("account_deleted", reason, false)
	}
}

func markAccountActed(store *stateStore, auth authFile, marker, reason string) {
	_, _ = store.upsertAccount(auth, func(r *accountRecord) {
		r.Action = marker
		r.ActedAt = float64(time.Now().Unix())
		r.Reason = reason
	})
}

func tierLabel(tier string) string {
	switch tier {
	case tierSoft:
		return "软阈值"
	case tierHard:
		return "硬阈值"
	case tierFail:
		return "连续失败"
	default:
		return tier
	}
}
