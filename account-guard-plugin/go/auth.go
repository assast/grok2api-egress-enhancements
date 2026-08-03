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
	return nil
}

func isAuthExpired(auth authFile) bool {
	exp, _ := auth.Raw["expired"].(string)
	if exp == "" {
		return false
	}
	// accept RFC3339 / RFC3339Nano / trailing Z variants
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, exp); err == nil {
			return time.Now().After(t.Add(-2 * time.Minute))
		}
	}
	// bare "2026-08-02T05:04:09Z" already RFC3339
	if t, err := time.Parse("2006-01-02T15:04:05Z07:00", exp); err == nil {
		return time.Now().After(t.Add(-2 * time.Minute))
	}
	return false
}

// countEnabledAccounts reports how many xAI accounts are currently usable
// (present and not disabled). Drives the min_keep_accounts safety valve.
func countEnabledAccounts() (int, error) {
	auths, err := listAuthFiles()
	if err != nil {
		return 0, err
	}
	count := 0
	for _, a := range auths {
		if !a.Disabled {
			count++
		}
	}
	return count, nil
}
