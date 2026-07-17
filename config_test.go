package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfigIsValid(t *testing.T) {
	if err := defaultConfig().validate(); err != nil {
		t.Fatalf("default config is invalid: %v", err)
	}
}

func TestDuplicateCountryIsRejected(t *testing.T) {
	cfg := defaultConfig()
	cfg.Countries = append(cfg.Countries, Country{Code: "US", Name: "duplicate"})
	if err := cfg.validate(); err == nil {
		t.Fatal("expected duplicate country error")
	}
}

func TestUpstreamProxySettingsRejectNewlines(t *testing.T) {
	cfg := defaultConfig()
	cfg.UpstreamSOCKS5 = "proxy.example:1080\r\nSETCONF Unsafe=1"
	if err := cfg.validate(); err == nil {
		t.Fatal("upstream proxy address with a newline was accepted")
	}
	cfg = defaultConfig()
	cfg.UpstreamSOCKS5 = "proxy.example:1080"
	cfg.UpstreamPassword = "secret\nvalue"
	if err := cfg.validate(); err == nil {
		t.Fatal("upstream proxy password with a newline was accepted")
	}
}

func TestUpstreamProxyCredentialsMustBePaired(t *testing.T) {
	cfg := defaultConfig()
	cfg.UpstreamSOCKS5 = "proxy.example:1080"
	cfg.UpstreamUsername = "user"
	if err := cfg.validate(); err == nil {
		t.Fatal("upstream proxy username without password was accepted")
	}
	cfg = defaultConfig()
	cfg.UpstreamSOCKS5 = "proxy.example:1080"
	cfg.UpstreamPassword = "password"
	if err := cfg.validate(); err == nil {
		t.Fatal("upstream proxy password without username was accepted")
	}
}

func TestClientAPIKeyMinimumLength(t *testing.T) {
	cfg := defaultConfig()
	cfg.ClientAPIKey = "123456"
	if err := cfg.validate(); err != nil {
		t.Fatalf("six-character client API key was rejected: %v", err)
	}
	cfg.ClientAPIKey = "12345"
	if err := cfg.validate(); err == nil {
		t.Fatal("five-character client API key was accepted")
	}
}

func TestPortsAreStable(t *testing.T) {
	cfg := defaultConfig()
	manager := NewManager(cfg)
	state := manager.State()
	for index, instance := range state.Instances {
		want := cfg.BaseSocksPort + index
		if instance.SocksPort != want {
			t.Fatalf("country %s has port %d, want %d", instance.Country.Code, instance.SocksPort, want)
		}
	}
}

func TestCountryProxyPortsAreStable(t *testing.T) {
	tests := map[string]int{"aa": 20000, "jp": 20249, "us": 20538, "zz": 20675}
	for code, want := range tests {
		got, err := countryPort(20000, code)
		if err != nil {
			t.Fatalf("countryPort(%q): %v", code, err)
		}
		if got != want {
			t.Fatalf("countryPort(%q) = %d, want %d", code, got, want)
		}
	}
}

func TestStateAPIAndWebPage(t *testing.T) {
	cfg := defaultConfig()
	cfg.StateDir = t.TempDir()
	cfg.AuthToken = ""
	authStore, err := NewAuthStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configStore := NewConfigStore(filepath.Join(t.TempDir(), "config.json"), cfg)
	manager := NewManager(cfg)
	handler := routes(manager, NewExitCatalog(cfg), configStore, authStore, cfg)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/countries", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("client API without key returned %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/state", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusPreconditionRequired {
		t.Fatalf("unconfigured API returned %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodPost, "/api/setup-password", strings.NewReader(`{"password":"test-password"}`))
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || len(response.Result().Cookies()) != 1 {
		t.Fatalf("password setup returned %d: %s", response.Code, response.Body.String())
	}
	sessionCookie := response.Result().Cookies()[0]

	request = httptest.NewRequest(http.MethodGet, "/api/state", nil)
	request.AddCookie(sessionCookie)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"proxy_address"`) {
		t.Fatalf("authenticated API returned %d: %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPut, "/api/settings/runtime", strings.NewReader(`{"max_running":3}`))
	request.AddCookie(sessionCookie)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || manager.State().MaxRunning != 3 {
		t.Fatalf("runtime settings returned %d: %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Tor 国家出口") || !strings.Contains(response.Body.String(), `id="running-instances"`) {
		t.Fatalf("web page returned %d", response.Code)
	}
}

func TestPasswordHash(t *testing.T) {
	hash, err := hashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatal(err)
	}
	if !verifyPassword(hash, "correct-horse-battery-staple") {
		t.Fatal("valid password was rejected")
	}
	if verifyPassword(hash, "wrong-password") {
		t.Fatal("invalid password was accepted")
	}
}

func TestRuntimeUpdateDoesNotPersistEnvironmentProxy(t *testing.T) {
	t.Setenv("TOR_UPSTREAM_SOCKS5", "proxy.example:1080")
	t.Setenv("TOR_UPSTREAM_USERNAME", "environment-user")
	t.Setenv("TOR_UPSTREAM_PASSWORD", "environment-secret")
	path := filepath.Join(t.TempDir(), "config.json")
	loaded, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Effective.UpstreamPassword != "environment-secret" {
		t.Fatal("environment proxy was not applied to effective config")
	}
	store := NewConfigStore(path, loaded.Stored)
	runtimeSettings := store.Runtime()
	runtimeSettings.MaxRunning = 7
	if err := store.UpdateRuntime(runtimeSettings); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "environment-secret") || strings.Contains(string(b), "environment-user") {
		t.Fatal("environment proxy credentials were persisted")
	}
}

func TestGeneratedClientAPIKeyIsSaved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	store := NewConfigStore(path, defaultConfig())
	key, err := store.UpdateClient(ClientUpdate{Host: "127.0.0.1", BasePort: 21000, RegenerateKey: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(key) < 40 {
		t.Fatal("generated client API key is too short")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), key) {
		t.Fatal("generated client API key was not saved")
	}
}

func TestClientAPIKeyUpdateAppliesImmediately(t *testing.T) {
	cfg := defaultConfig()
	cfg.ClientAPIKey = "original-secret-value"
	manager := NewManager(cfg)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/countries", nil)
	request.Header.Set("Authorization", "Bearer original-secret-value")
	if !validBearerToken(request, manager.clientAuth) {
		t.Fatal("original client API key was rejected")
	}
	manager.UpdateClientAPIKey("replacement-secret-value")
	if validBearerToken(request, manager.clientAuth) {
		t.Fatal("old client API key remained valid after hot update")
	}
	request.Header.Set("Authorization", "Bearer replacement-secret-value")
	if !validBearerToken(request, manager.clientAuth) {
		t.Fatal("replacement client API key was not applied")
	}
}

func TestLoadedConfigKeepsStoredAndEffectiveSnapshotsSeparate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	stored := defaultConfig()
	stored.UpstreamSOCKS5 = "stored.example:1080"
	stored.UpstreamUsername = "stored-user"
	stored.UpstreamPassword = "stored-secret"
	b, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o640); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TOR_UPSTREAM_SOCKS5", "environment.example:1080")
	t.Setenv("TOR_UPSTREAM_USERNAME", "environment-user")
	t.Setenv("TOR_UPSTREAM_PASSWORD", "environment-secret")
	t.Setenv("TOR_CLIENT_API_KEY", "environment-api-key")

	loaded, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Stored.UpstreamSOCKS5 != "stored.example:1080" || loaded.Stored.UpstreamPassword != "stored-secret" {
		t.Fatal("stored config was changed by environment overrides")
	}
	if loaded.Effective.UpstreamSOCKS5 != "environment.example:1080" || loaded.Effective.UpstreamPassword != "environment-secret" {
		t.Fatal("effective config did not receive environment overrides")
	}
	if loaded.Stored.ClientAPIKey != "" || loaded.Effective.ClientAPIKey != "environment-api-key" {
		t.Fatal("client API key snapshots were not kept separate")
	}

	store := NewConfigStore(path, loaded.Stored)
	runtimeSettings := store.Runtime()
	runtimeSettings.MaxRunning = 7
	if err := store.UpdateRuntime(runtimeSettings); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(saved), "environment-secret") || strings.Contains(string(saved), "environment-api-key") || !strings.Contains(string(saved), "stored-secret") {
		t.Fatal("saved config did not preserve the stored snapshot")
	}
}

func TestRuntimeUpdateIsAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	store := NewConfigStore(path, defaultConfig())
	before := store.Runtime()
	err := store.UpdateRuntime(RuntimeSettings{MaxRunning: 7, CircuitRotateMinutes: 1441})
	if err == nil {
		t.Fatal("invalid runtime settings should be rejected")
	}
	if after := store.Runtime(); after != before {
		t.Fatalf("runtime settings changed after failed update: before=%+v after=%+v", before, after)
	}
}
