package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type hostAuthListResponse struct {
	Files []pluginapi.HostAuthFileEntry `json:"files"`
}

type hostAuthGetResponse struct {
	AuthIndex string          `json:"auth_index"`
	Name      string          `json:"name,omitempty"`
	Path      string          `json:"path,omitempty"`
	JSON      json.RawMessage `json:"json"`
}

type authFile struct {
	Index    string
	Name     string
	Path     string
	Email    string
	Disabled bool
	ProxyURL string
	Raw      map[string]any
}

func listAuthFiles() ([]authFile, error) {
	raw, err := callHost(pluginabi.MethodHostAuthList, mustJSON(map[string]any{}))
	if err != nil {
		return nil, err
	}
	var resp hostAuthListResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		// some hosts return bare array
		var files []pluginapi.HostAuthFileEntry
		if err2 := json.Unmarshal(raw, &files); err2 != nil {
			return nil, fmt.Errorf("decode auth list: %w", err)
		}
		resp.Files = files
	}
	out := make([]authFile, 0, len(resp.Files))
	for _, f := range resp.Files {
		idx := strings.TrimSpace(f.AuthIndex)
		if idx == "" {
			idx = strings.TrimSpace(f.ID)
		}
		if idx == "" {
			idx = strings.TrimSpace(f.Name)
		}
		if idx == "" {
			continue
		}
		// prefer xai provider/type from list entry
		prov := strings.ToLower(strings.TrimSpace(f.Provider + " " + f.Type + " " + f.Name))
		if prov != "" && !strings.Contains(prov, "xai") {
			continue
		}
		got, err := getAuthFile(idx)
		if err != nil {
			// try by name
			if f.Name != "" {
				got, err = getAuthFile(f.Name)
			}
			if err != nil {
				continue
			}
		}
		if t, _ := got.Raw["type"].(string); strings.ToLower(t) != "xai" && strings.ToLower(t) != "" {
			if !strings.HasPrefix(strings.ToLower(got.Name), "xai-") {
				continue
			}
		}
		out = append(out, got)
	}
	return out, nil
}

func getAuthFile(authIndex string) (authFile, error) {
	raw, err := callHost(pluginabi.MethodHostAuthGet, mustJSON(map[string]any{"auth_index": authIndex}))
	if err != nil {
		// try name field
		raw, err = callHost(pluginabi.MethodHostAuthGet, mustJSON(map[string]any{"name": authIndex}))
		if err != nil {
			return authFile{}, err
		}
	}
	var resp hostAuthGetResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return authFile{}, err
	}
	obj := map[string]any{}
	if len(resp.JSON) > 0 {
		_ = json.Unmarshal(resp.JSON, &obj)
	}
	email, _ := obj["email"].(string)
	proxy, _ := obj["proxy_url"].(string)
	disabled, _ := obj["disabled"].(bool)
	name := resp.Name
	if name == "" {
		name = filepath.Base(resp.Path)
	}
	if name == "" && email != "" {
		name = "xai-" + email + ".json"
	}
	idx := resp.AuthIndex
	if idx == "" {
		idx = authIndex
	}
	return authFile{
		Index:    idx,
		Name:     name,
		Path:     resp.Path,
		Email:    email,
		Disabled: disabled,
		ProxyURL: strings.TrimSpace(proxy),
		Raw:      obj,
	}, nil
}

func saveAuthFile(name string, obj map[string]any) error {
	if name == "" {
		return fmt.Errorf("auth name required")
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	_, err = callHost(pluginabi.MethodHostAuthSave, mustJSON(map[string]any{
		"name": name,
		"json": json.RawMessage(raw),
	}))
	return err
}

func setAuthProxyAndFlags(a authFile, proxyURL string, disabled bool, reason string) error {
	if a.Raw == nil {
		a.Raw = map[string]any{}
	}
	if proxyURL == "" {
		delete(a.Raw, "proxy_url")
	} else {
		a.Raw["proxy_url"] = proxyURL
	}
	a.Raw["disabled"] = disabled
	if disabled && reason != "" {
		a.Raw["disabled_reason"] = reason
		a.Raw["disabled_at"] = nowRFC3339()
	} else {
		delete(a.Raw, "disabled_reason")
		delete(a.Raw, "disabled_at")
	}
	// ensure type
	if _, ok := a.Raw["type"]; !ok {
		a.Raw["type"] = "xai"
	}
	return saveAuthFile(a.Name, a.Raw)
}

// deleteAuthFile disables the credential through the host before deleting its
// physical file. The native host ABI has no delete callback; this guarded path
// is valid only for file-backed credentials, which is the CPA deployment model.
func deleteAuthFile(a authFile, reason string) error {
	name := strings.TrimSpace(a.Name)
	path := filepath.Clean(strings.TrimSpace(a.Path))
	if name == "" || filepath.Base(name) != name || !strings.HasSuffix(strings.ToLower(name), ".json") {
		return fmt.Errorf("账号文件名无效")
	}
	if path == "." || filepath.Base(path) != name {
		return fmt.Errorf("账号不是可安全删除的本地文件")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("读取账号文件失败: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("账号不是常规文件")
	}
	if err := setAuthProxyAndFlags(a, a.ProxyURL, true, reason); err != nil {
		return fmt.Errorf("下线账号失败: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("删除账号文件失败: %w", err)
	}
	authProxyMu.Lock()
	authProxyCache = nil
	authProxyAt = time.Time{}
	authProxyMu.Unlock()
	return nil
}

func rebalanceAuthsToNodes(store *stateStore) (map[string]int, error) {
	auths, err := listAuthFiles()
	if err != nil {
		return nil, err
	}
	nodes := store.listNodes()
	// eligible nodes: enabled, not guard-quarantined, has proxy
	eligible := make([]*nodeRecord, 0)
	for _, n := range nodes {
		if n.Enabled && !n.DisabledByGuard && n.ProxyURL != "" {
			eligible = append(eligible, n)
		}
	}
	counts := map[string]int{}
	if len(eligible) == 0 {
		// clear proxies? keep as-is but zero counts
		store.setAssignedCounts(counts)
		return counts, fmt.Errorf("没有可调度出口节点")
	}
	// only rebalance non-disabled auths; disabled stay put
	active := make([]authFile, 0)
	for _, a := range auths {
		if a.Disabled {
			// still count if matches a node proxy
			for _, n := range nodes {
				if a.ProxyURL != "" && a.ProxyURL == n.ProxyURL {
					counts[n.ID]++
				}
			}
			continue
		}
		active = append(active, a)
	}
	// capacity-aware round robin
	cursor := 0
	for _, a := range active {
		// pick next node with capacity room
		var chosen *nodeRecord
		for tried := 0; tried < len(eligible); tried++ {
			n := eligible[cursor%len(eligible)]
			cursor++
			cap := n.AccountCapacity
			if cap > 0 && counts[n.ID] >= cap {
				continue
			}
			chosen = n
			break
		}
		if chosen == nil {
			// all full — pile on last eligible
			chosen = eligible[len(eligible)-1]
		}
		if a.ProxyURL == chosen.ProxyURL && !a.Disabled {
			counts[chosen.ID]++
			continue
		}
		if err := setAuthProxyAndFlags(a, chosen.ProxyURL, false, ""); err != nil {
			return counts, fmt.Errorf("绑定 %s 失败: %w", a.Name, err)
		}
		counts[chosen.ID]++
	}
	store.setAssignedCounts(counts)
	return counts, nil
}

func refreshAssignedCounts(store *stateStore) {
	auths, err := listAuthFiles()
	if err != nil {
		return
	}
	nodes := store.listNodes()
	byProxy := map[string]string{}
	for _, n := range nodes {
		if n.ProxyURL != "" {
			byProxy[n.ProxyURL] = n.ID
		}
	}
	counts := map[string]int{}
	for _, a := range auths {
		if id, ok := byProxy[a.ProxyURL]; ok {
			counts[id]++
		}
	}
	store.setAssignedCounts(counts)
}

func disableAuthsOnNode(store *stateStore, node *nodeRecord, reason string) error {
	if node == nil || node.ProxyURL == "" {
		return nil
	}
	auths, err := listAuthFiles()
	if err != nil {
		return err
	}
	for _, a := range auths {
		if a.ProxyURL == node.ProxyURL && !a.Disabled {
			_ = setAuthProxyAndFlags(a, a.ProxyURL, true, reason)
		}
	}
	return nil
}

func enableAuthsOnNode(node *nodeRecord) error {
	if node == nil || node.ProxyURL == "" {
		return nil
	}
	auths, err := listAuthFiles()
	if err != nil {
		return err
	}
	for _, a := range auths {
		if a.ProxyURL == node.ProxyURL && a.Disabled {
			reason, _ := a.Raw["disabled_reason"].(string)
			if strings.Contains(reason, "egress-guard") || strings.Contains(reason, "降智") || reason == "" {
				_ = setAuthProxyAndFlags(a, a.ProxyURL, false, "")
			}
		}
	}
	return nil
}

func pickAuthForNode(node *nodeRecord) (authFile, error) {
	list, err := listAuthsForNode(node, 1)
	if err != nil {
		return authFile{}, err
	}
	if len(list) == 0 {
		return authFile{}, fmt.Errorf("没有可用的 CPA xAI 账号")
	}
	return list[0], nil
}

// listAuthsForNode returns enabled xAI auths bound to the node proxy, preferring
// non-expired tokens. A positive limit caps the result; zero returns all candidates.
func listAuthsForNode(node *nodeRecord, limit int) ([]authFile, error) {
	auths, err := listAuthFiles()
	if err != nil {
		return nil, err
	}
	var primary, fallback, expired []authFile
	for _, a := range auths {
		if a.Disabled {
			continue
		}
		tok, _ := a.Raw["access_token"].(string)
		if strings.TrimSpace(tok) == "" {
			continue
		}
		onNode := node != nil && node.ProxyURL != "" && a.ProxyURL == node.ProxyURL
		if isAuthExpired(a) {
			if onNode {
				expired = append(expired, a)
			}
			continue
		}
		if onNode {
			primary = append(primary, a)
		} else {
			fallback = append(fallback, a)
		}
	}
	out := make([]authFile, 0, limit)
	out = append(out, primary...)
	// If node has no fresh bound auth, still try expired bound ones before foreign auths
	// so quality probe still pins to the channel when possible.
	if len(out) == 0 {
		out = append(out, expired...)
	}
	if limit <= 0 || len(out) < limit {
		out = append(out, fallback...)
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("没有可用的 CPA xAI 账号")
	}
	return out, nil
}

func listProbeAuthsForNode(store *stateStore, node *nodeRecord, limit int) ([]authFile, bool, error) {
	auths, err := listAuthsForNode(node, 0)
	if err != nil {
		return nil, false, err
	}
	if limit <= 0 {
		limit = 8
	}
	available := make([]authFile, 0, limit)
	cooling := false
	now := time.Now()
	for _, auth := range auths {
		if store.isAccountCooling(auth, now) {
			cooling = true
			continue
		}
		available = append(available, auth)
		if len(available) == limit {
			break
		}
	}
	return available, cooling, nil
}

func rebindAuthsToNode(auths []authFile, sourceProxy string, destination *nodeRecord) (int, error) {
	if destination == nil || destination.ProxyURL == "" {
		return 0, fmt.Errorf("保留节点缺少代理")
	}
	moved := 0
	for _, auth := range auths {
		if auth.ProxyURL != sourceProxy || sourceProxy == destination.ProxyURL {
			continue
		}
		reason, _ := auth.Raw["disabled_reason"].(string)
		if err := setAuthProxyAndFlags(auth, destination.ProxyURL, auth.Disabled, reason); err != nil {
			return moved, fmt.Errorf("改绑账号 %s 失败: %w", auth.Name, err)
		}
		moved++
	}
	return moved, nil
}

func deduplicateExitIPNodes(store *stateStore) ([]exitIPDedupGroup, int, error) {
	groups := planExitIPDedup(store.listNodes())
	if len(groups) == 0 {
		return groups, 0, nil
	}
	auths, err := listAuthFiles()
	if err != nil {
		return nil, 0, err
	}
	deleteIDs := make([]string, 0)
	moved := 0
	for _, group := range groups {
		keep, ok := store.getNode(group.KeepID)
		if !ok {
			return nil, moved, fmt.Errorf("保留节点 %s 不存在", group.KeepID)
		}
		for _, deleteID := range group.DeleteIDs {
			duplicate, ok := store.getNode(deleteID)
			if !ok {
				continue
			}
			count, err := rebindAuthsToNode(auths, duplicate.ProxyURL, keep)
			if err != nil {
				return nil, moved, err
			}
			moved += count
			deleteIDs = append(deleteIDs, deleteID)
		}
	}
	if err := store.deleteNodes(deleteIDs); err != nil {
		return nil, moved, err
	}
	refreshAssignedCounts(store)
	for _, group := range groups {
		store.appendEvent(guardEvent{
			Event:    "exit_ip_deduplicated",
			NodeID:   group.KeepID,
			NodeName: "出口 " + group.ExitIP,
			Reason:   fmt.Sprintf("保留节点 %s，剔除 %d 个重复节点", group.KeepID, len(group.DeleteIDs)),
		})
	}
	return groups, moved, nil
}

// listBoundAuthSummaries returns lightweight account info for a node (no secrets).
func listBoundAuthSummaries(node *nodeRecord) ([]map[string]any, error) {
	auths, err := listAuthFiles()
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0)
	if node == nil || node.ProxyURL == "" {
		return out, nil
	}
	for _, a := range auths {
		if a.ProxyURL != node.ProxyURL {
			continue
		}
		out = append(out, map[string]any{
			"name":     a.Name,
			"email":    a.Email,
			"disabled": a.Disabled,
			"expired":  isAuthExpired(a),
		})
	}
	return out, nil
}

// migrateAuthsOffNode moves enabled auths off a quarantined node onto healthy nodes.
func migrateAuthsOffNode(store *stateStore, bad *nodeRecord) error {
	if bad == nil || bad.ProxyURL == "" {
		return nil
	}
	auths, err := listAuthFiles()
	if err != nil {
		return err
	}
	healthy := make([]*nodeRecord, 0)
	for _, n := range store.listNodes() {
		if n.ID == bad.ID {
			continue
		}
		if n.Enabled && !n.DisabledByGuard && n.ProxyURL != "" {
			healthy = append(healthy, n)
		}
	}
	if len(healthy) == 0 {
		// no destination — just disable in place
		return disableAuthsOnNode(store, bad, "egress-guard 降智隔离: 无健康通道可迁移")
	}
	cursor := 0
	moved := 0
	for _, a := range auths {
		if a.ProxyURL != bad.ProxyURL {
			continue
		}
		dest := healthy[cursor%len(healthy)]
		cursor++
		// re-enable if previously guard-disabled, bind to healthy proxy
		if err := setAuthProxyAndFlags(a, dest.ProxyURL, false, ""); err != nil {
			continue
		}
		moved++
	}
	refreshAssignedCounts(store)
	if moved > 0 {
		store.appendEvent(guardEvent{
			Event:    "accounts_migrated",
			NodeID:   bad.ID,
			NodeName: bad.Name,
			Reason:   fmt.Sprintf("隔离后迁出 %d 个账号到健康通道", moved),
		})
	}
	return nil
}
