package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);

static const cliproxy_host_api* stored_host;

static void store_host_api(const cliproxy_host_api* host) {
	stored_host = host;
}

static int call_host_api(const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	if (stored_host == NULL || stored_host->call == NULL) {
		return 1;
	}
	return stored_host->call(stored_host->host_ctx, method, request, request_len, response);
}

static void free_host_buffer(void* ptr, size_t len) {
	if (stored_host != NULL && stored_host->free_buffer != NULL && ptr != NULL) {
		stored_host->free_buffer(ptr, len);
	}
}
*/
import "C"

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"gopkg.in/yaml.v3"
)

const (
	pluginName          = "grok2api-account-guard"
	pluginVersion       = "1.0.0"
	resourcePath        = "/status"
	managementAPIPath   = "/v0/management/grok2api-account-guard/api"
	managementUIHeader  = "X-Grok2API-Account-Guard-UI"
	resourceContentType = "text/html; charset=utf-8"
	defaultStateFile    = "/CLIProxyAPI/plugin-data/account-guard/state.json"
	// maxProbeBatch caps one quality-test request; the UI chunks larger
	// selections so no single management request runs long.
	maxProbeBatch = 5
)

//go:embed page.html
var pageTemplate string

//go:embed tokens.css
var tokenCSS string

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type lifecycleRequest struct {
	ConfigYAML []byte `json:"config_yaml"`
}

type pluginConfig struct {
	StateFile string `yaml:"state_file" json:"state_file"`
}

type registration struct {
	SchemaVersion uint32                   `json:"schema_version"`
	Metadata      pluginapi.Metadata       `json:"metadata"`
	Capabilities  registrationCapabilities `json:"capabilities"`
}

type registrationCapabilities struct {
	ManagementAPI bool `json:"management_api"`
	UsagePlugin   bool `json:"usage_plugin"`
}

type managementRegistration struct {
	Routes    []managementRoute    `json:"routes,omitempty"`
	Resources []managementResource `json:"resources,omitempty"`
}

type managementRoute struct {
	Method      string `json:"Method"`
	Path        string `json:"Path"`
	Description string `json:"Description"`
}

type managementResource struct {
	Path        string `json:"Path"`
	Menu        string `json:"Menu"`
	Description string `json:"Description"`
}

type managementRequest struct {
	Method  string
	Path    string
	Headers http.Header
	Query   url.Values
	Body    []byte
}

type uiProxyRequest struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body,omitempty"`
}

type managementResponse struct {
	StatusCode int         `json:"StatusCode"`
	Headers    http.Header `json:"Headers"`
	Body       []byte      `json:"Body"`
}

var (
	store         *stateStore
	currentConfig atomic.Value // pluginConfig
	startedAt     = time.Now().UTC()
)

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	C.store_host_api(host)
	currentConfig.Store(pluginConfig{StateFile: defaultStateFile})
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 1
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, errHandle := handleMethod(C.GoString(method), requestBytes)
	if errHandle != nil {
		writeResponse(response, errorEnvelope("plugin_error", errHandle.Error()))
		return 1
	}
	writeResponse(response, raw)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, len C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
	_ = len
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {}

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		if err := configure(request); err != nil {
			return nil, err
		}
		return okEnvelope(pluginRegistration())
	case pluginabi.MethodManagementRegister:
		return okEnvelope(managementRegistration{
			Routes:    []managementRoute{{Method: http.MethodPost, Path: "/grok2api-account-guard/api", Description: "CPA 账号守护 UI API"}},
			Resources: []managementResource{{Path: resourcePath, Menu: "账号守护", Description: "被动账号质量守护 · 降智自动停用/删除（不依赖出口节点）"}},
		})
	case pluginabi.MethodManagementHandle:
		return handleManagement(request)
	case pluginabi.MethodUsageHandle:
		return handleUsage(request)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func configure(raw []byte) error {
	var req lifecycleRequest
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			return err
		}
	}
	cfg := pluginConfig{StateFile: defaultStateFile}
	if len(req.ConfigYAML) > 0 {
		if err := yaml.Unmarshal(req.ConfigYAML, &cfg); err != nil {
			return err
		}
	}
	if strings.TrimSpace(cfg.StateFile) == "" {
		cfg.StateFile = defaultStateFile
	}
	currentConfig.Store(cfg)
	// Purely passive: no background worker, everything is usage driven.
	store = newStateStore(cfg.StateFile)
	return nil
}

func pluginRegistration() registration {
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             pluginName,
			Version:          pluginVersion,
			Author:           "lij768423-svg",
			GitHubRepository: "https://github.com/lij768423-svg/grok2api-egress-enhancements",
			ConfigFields: []pluginapi.ConfigField{
				{Name: "state_file", Type: pluginapi.ConfigFieldTypeString, Description: "账号守护状态文件路径（策略/账号状态/事件）"},
			},
		},
		Capabilities: registrationCapabilities{ManagementAPI: true, UsagePlugin: true},
	}
}

func handleManagement(request []byte) ([]byte, error) {
	var req managementRequest
	if len(request) > 0 {
		if err := json.Unmarshal(request, &req); err != nil {
			return nil, err
		}
	}
	path := strings.TrimSpace(req.Path)
	if path == "" {
		path = resourcePath
	}
	base := "/v0/resource/plugins/" + pluginName
	switch {
	case path == resourcePath, path == "/", path == base, path == base+"/", path == base+resourcePath, strings.HasSuffix(path, "/status"):
		return okEnvelope(managementResponse{
			StatusCode: http.StatusOK,
			Headers:    http.Header{"content-type": []string{resourceContentType}},
			Body:       []byte(strings.Replace(pageTemplate, "/*__HALLMARK_TOKENS__*/", tokenCSS, 1)),
		})
	case path == managementAPIPath:
		return handleUIProxy(req)
	default:
		return okEnvelope(managementResponse{
			StatusCode: http.StatusNotFound,
			Headers:    http.Header{"content-type": []string{"text/plain; charset=utf-8"}},
			Body:       []byte("not found"),
		})
	}
}

func handleUIProxy(req managementRequest) ([]byte, error) {
	if !strings.EqualFold(strings.TrimSpace(req.Method), http.MethodPost) || req.Headers.Get(managementUIHeader) != "1" {
		return managementJSON(http.StatusForbidden, errMsg("forbidden", "forbidden"))
	}
	var input uiProxyRequest
	if len(req.Body) == 0 || json.Unmarshal(req.Body, &input) != nil {
		return managementJSON(http.StatusBadRequest, errMsg("invalidRequest", "invalid request"))
	}
	parsed, err := url.ParseRequestURI(strings.TrimSpace(input.Path))
	if err != nil || parsed.IsAbs() || parsed.Fragment != "" || !strings.HasPrefix(parsed.Path, "/") {
		return managementJSON(http.StatusBadRequest, errMsg("invalidPath", "invalid path"))
	}
	method := strings.ToUpper(strings.TrimSpace(input.Method))
	if method == "" {
		method = http.MethodGet
	}
	return dispatchAPI(method, parsed.Path, parsed.Query(), input.Body)
}

func dispatchAPI(method, path string, query url.Values, body json.RawMessage) ([]byte, error) {
	ensureStore()
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		path = "/"
	}

	switch path {
	case "/status", "/account-guard":
		if method != http.MethodGet {
			return managementJSON(http.StatusMethodNotAllowed, errMsg("methodNotAllowed", "method not allowed"))
		}
		return managementJSON(http.StatusOK, buildStatus())

	case "/policy":
		if method == http.MethodGet {
			return managementJSON(http.StatusOK, map[string]any{"data": store.policy(), "config": store.policy()})
		}
		if method == http.MethodPut || method == http.MethodPost {
			var raw map[string]any
			if err := json.Unmarshal(body, &raw); err != nil {
				return managementJSON(http.StatusBadRequest, errMsg("invalidBody", "invalid body"))
			}
			p := store.policy()
			p.SoftTPS = floatPick(raw, p.SoftTPS, "soft_tps", "softTPS")
			p.HardTPS = floatPick(raw, p.HardTPS, "hard_tps", "hardTPS")
			p.ConsecutiveSoft = intPick(raw, p.ConsecutiveSoft, "consecutive_soft", "consecutiveSoft")
			p.ConsecutiveFail = intPick(raw, p.ConsecutiveFail, "consecutive_fail", "consecutiveFail")
			p.SoftAction = stringPick(raw, p.SoftAction, "soft_action", "softAction")
			p.HardAction = stringPick(raw, p.HardAction, "hard_action", "hardAction")
			p.FailAction = stringPick(raw, p.FailAction, "fail_action", "failAction")
			p.MinKeepAccounts = intPick(raw, p.MinKeepAccounts, "min_keep_accounts", "minKeepAccounts")
			p.DryRun = boolPick(raw, p.DryRun, "dry_run", "dryRun")
			p.ProbeModel = stringPick(raw, p.ProbeModel, "probe_model", "probeModel")
			p.ProbeMaxTokens = intPick(raw, p.ProbeMaxTokens, "probe_max_tokens", "probeMaxTokens")
			if err := store.updatePolicy(p); err != nil {
				return managementJSON(http.StatusBadRequest, errMsg("invalidPolicy", err.Error()))
			}
			return managementJSON(http.StatusOK, map[string]any{"data": store.policy(), "ok": true})
		}

	case "/accounts/quality-test":
		if method != http.MethodPost {
			return managementJSON(http.StatusMethodNotAllowed, errMsg("methodNotAllowed", "method not allowed"))
		}
		var raw map[string]any
		_ = json.Unmarshal(body, &raw)
		keys := stringList(raw["keys"])
		if s := stringPick(raw, "", "key"); s != "" {
			keys = append(keys, s)
		}
		if len(keys) == 0 {
			return managementJSON(http.StatusBadRequest, errMsg("invalidBody", "keys 必填"))
		}
		if len(keys) > maxProbeBatch {
			return managementJSON(http.StatusBadRequest, errMsg("tooManyKeys", fmt.Sprintf("单次最多检测 %d 个账号", maxProbeBatch)))
		}
		results, err := runQualityProbes(store, keys)
		if err != nil {
			return managementJSON(http.StatusBadRequest, errMsg("probeFailed", err.Error()))
		}
		return managementJSON(http.StatusOK, map[string]any{"data": map[string]any{"results": results}, "results": results})
	}

	return managementJSON(http.StatusNotFound, errMsg("notFound", "not found"))
}

// buildAccountViews joins live CPA accounts with guard state. Records whose
// account file is gone (deleted by this plugin) are kept as history.
func buildAccountViews() []map[string]any {
	records := map[string]*accountRecord{}
	for _, rec := range store.listAccounts() {
		records[rec.Key] = rec
	}
	out := make([]map[string]any, 0, len(records))
	seen := map[string]bool{}
	if auths, err := listAuthFiles(); err == nil {
		for _, a := range auths {
			key := accountKey(a)
			seen[key] = true
			out = append(out, accountView(key, a, records[key], true))
		}
	}
	for key, rec := range records {
		if seen[key] {
			continue
		}
		out = append(out, accountView(key, authFile{Name: rec.Name, Email: rec.Email, Index: rec.Index}, rec, false))
	}
	sort.Slice(out, func(i, j int) bool {
		return fmt.Sprint(out[i]["name"]) < fmt.Sprint(out[j]["name"])
	})
	return out
}

func accountView(key string, a authFile, rec *accountRecord, present bool) map[string]any {
	view := map[string]any{
		"key":      key,
		"name":     a.Name,
		"email":    a.Email,
		"index":    a.Index,
		"present":  present,
		"disabled": a.Disabled,
		"expired":  present && isAuthExpired(a),
	}
	if rec == nil {
		rec = &accountRecord{}
	}
	view["soft_strikes"] = rec.SoftStrikes
	view["fail_strikes"] = rec.FailStrikes
	view["last_classification"] = rec.LastClassification
	view["last_output_tps"] = rec.LastOutputTPS
	view["last_output_tokens"] = rec.LastOutputTokens
	view["last_duration_ms"] = rec.LastDurationMs
	view["last_first_token_ms"] = rec.LastFirstTokenMs
	view["last_observed_at"] = rec.LastObservedAt
	view["last_source"] = rec.LastSource
	view["observed_count"] = rec.ObservedCount
	view["action"] = rec.Action
	view["acted_at"] = rec.ActedAt
	view["reason"] = rec.Reason
	return view
}

func buildStatus() map[string]any {
	ensureStore()
	accounts := buildAccountViews()
	return map[string]any{
		"available":    true,
		"updatedAt":    store.snapshot().UpdatedAt,
		"config":       store.policy(),
		"editable":     true,
		"accounts":     accounts,
		"statistics":   store.stats(),
		"recentEvents": store.events(),
		"plugin":       pluginName,
		"version":      pluginVersion,
		"started_at":   startedAt.Format(time.RFC3339),
		"engine":       "cpa-account-guard",
		"hint":         "被动账号守护：按每个账号的输出 Token/s 与失败情况自动停用或删除，不依赖出口节点。",
	}
}

func handleUsage(request []byte) ([]byte, error) {
	ensureStore()
	var payload map[string]any
	if len(request) > 0 {
		_ = json.Unmarshal(request, &payload)
	}
	// Also accept nested record
	if rec, ok := payload["record"].(map[string]any); ok {
		payload = rec
	}
	handleAccountUsage(store, payload)
	return okEnvelope(map[string]any{"recorded": true})
}

func ensureStore() {
	if store == nil {
		cfg := pluginConfig{StateFile: defaultStateFile}
		if v := currentConfig.Load(); v != nil {
			if c, ok := v.(pluginConfig); ok {
				cfg = c
			}
		}
		store = newStateStore(cfg.StateFile)
	}
}

func managementJSON(status int, v any) ([]byte, error) {
	body, _ := json.Marshal(v)
	return okEnvelope(managementResponse{
		StatusCode: status,
		Headers:    http.Header{"content-type": []string{"application/json; charset=utf-8"}},
		Body:       body,
	})
}

func errMsg(code, message string) map[string]any {
	return map[string]any{"error": map[string]string{"code": code, "message": message}}
}

func intPick(raw map[string]any, def int, keys ...string) int {
	for _, k := range keys {
		if v, ok := raw[k]; ok {
			return int(anyInt(v))
		}
	}
	return def
}

func floatPick(raw map[string]any, def float64, keys ...string) float64 {
	for _, k := range keys {
		if v, ok := raw[k]; ok {
			switch t := v.(type) {
			case float64:
				return t
			case int:
				return float64(t)
			case json.Number:
				f, _ := t.Float64()
				return f
			}
		}
	}
	return def
}

func stringPick(raw map[string]any, def string, keys ...string) string {
	for _, k := range keys {
		if v, ok := raw[k].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return def
}

func boolPick(raw map[string]any, def bool, keys ...string) bool {
	for _, k := range keys {
		if v, ok := raw[k].(bool); ok {
			return v
		}
	}
	return def
}

func stringList(v any) []string {
	out := []string{}
	switch t := v.(type) {
	case []any:
		for _, x := range t {
			if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
	case []string:
		for _, s := range t {
			if strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
	}
	return out
}

func firstString(payload map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := payload[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	// nested
	for _, wrap := range []string{"usage", "meta", "request", "data"} {
		if m, ok := payload[wrap].(map[string]any); ok {
			if s := firstString(m, keys...); s != "" {
				return s
			}
		}
	}
	return ""
}

func firstInt(payload map[string]any, keys ...string) int64 {
	for _, k := range keys {
		if v, ok := payload[k]; ok {
			if n := anyInt(v); n != 0 {
				return n
			}
		}
	}
	return 0
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

func mustJSON(v any) []byte {
	raw, _ := json.Marshal(v)
	return raw
}

func callHost(method string, payload []byte) (json.RawMessage, error) {
	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))
	var response C.cliproxy_buffer
	var reqPtr *C.uint8_t
	if len(payload) > 0 {
		reqPtr = (*C.uint8_t)(C.CBytes(payload))
		defer C.free(unsafe.Pointer(reqPtr))
	}
	code := C.call_host_api(cMethod, reqPtr, C.size_t(len(payload)), &response)
	if code != 0 {
		return nil, fmt.Errorf("host callback %s code=%d", method, int(code))
	}
	if response.ptr == nil || response.len == 0 {
		return nil, fmt.Errorf("host callback %s empty", method)
	}
	raw := C.GoBytes(response.ptr, C.int(response.len))
	C.free_host_buffer(response.ptr, response.len)
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return raw, nil
	}
	if !env.OK {
		msg := "host error"
		if env.Error != nil {
			msg = env.Error.Message
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return append(json.RawMessage(nil), env.Result...), nil
}

func okEnvelope(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{OK: true, Result: raw})
}

func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message}})
	return raw
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil {
		return
	}
	if len(raw) == 0 {
		response.ptr = nil
		response.len = 0
		return
	}
	response.ptr = C.CBytes(raw)
	response.len = C.size_t(len(raw))
}
