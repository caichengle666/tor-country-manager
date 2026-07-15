package main

import (
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

	request := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	response := httptest.NewRecorder()
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
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Tor 国家出口") {
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
	cfg := defaultConfig()
	cfg.UpstreamSOCKS5 = "proxy.example:1080"
	cfg.UpstreamUsername = "environment-user"
	cfg.UpstreamPassword = "environment-secret"
	path := filepath.Join(t.TempDir(), "config.json")
	store := NewConfigStore(path, cfg)
	if err := store.UpdateMaxRunning(7); err != nil {
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
