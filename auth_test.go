package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuthNotConfiguredByDefault(t *testing.T) {
	cfg := defaultConfig()
	cfg.StateDir = t.TempDir()
	store, err := NewAuthStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if store.Configured() {
		t.Fatal("store should not be configured without a password or token")
	}
}

func TestAuthLegacyToken(t *testing.T) {
	cfg := defaultConfig()
	cfg.StateDir = t.TempDir()
	cfg.AuthToken = "legacy-secret"
	store, err := NewAuthStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !store.Configured() {
		t.Fatal("store should be configured with a legacy token")
	}
	if !store.Verify("legacy-secret") {
		t.Fatal("legacy token should verify")
	}
	if store.Verify("wrong-token") {
		t.Fatal("wrong token should not verify")
	}
}

func TestAuthSetupAndVerify(t *testing.T) {
	cfg := defaultConfig()
	cfg.StateDir = t.TempDir()
	store, err := NewAuthStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Setup("test-password-123"); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	if !store.Configured() {
		t.Fatal("store should be configured after setup")
	}
	if !store.Verify("test-password-123") {
		t.Fatal("correct password should verify")
	}
	if store.Verify("wrong-password") {
		t.Fatal("wrong password should not verify")
	}
	if store.Verify("") {
		t.Fatal("empty password should not verify")
	}
}

func TestAuthSetupRejectsShortPassword(t *testing.T) {
	cfg := defaultConfig()
	cfg.StateDir = t.TempDir()
	store, err := NewAuthStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Setup("short"); err == nil {
		t.Fatal("short password should be rejected")
	}
}

func TestAuthSetupTwiceFails(t *testing.T) {
	cfg := defaultConfig()
	cfg.StateDir = t.TempDir()
	store, err := NewAuthStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Setup("first-password"); err != nil {
		t.Fatal(err)
	}
	if err := store.Setup("second-password"); err == nil {
		t.Fatal("second setup should fail")
	}
}

func TestAuthChangePassword(t *testing.T) {
	cfg := defaultConfig()
	cfg.StateDir = t.TempDir()
	store, err := NewAuthStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Setup("original-password"); err != nil {
		t.Fatal(err)
	}
	if err := store.Change("wrong-password", "new-password"); err == nil {
		t.Fatal("change with wrong current password should fail")
	}
	if err := store.Change("original-password", "new-password-here"); err != nil {
		t.Fatalf("change with correct current password failed: %v", err)
	}
	if !store.Verify("new-password-here") {
		t.Fatal("new password should verify")
	}
	if store.Verify("original-password") {
		t.Fatal("old password should not verify after change")
	}
}

func TestAuthSessionLifecycle(t *testing.T) {
	cfg := defaultConfig()
	cfg.StateDir = t.TempDir()
	store, err := NewAuthStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	if err := store.CreateSession(rec); err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookieName {
		t.Fatalf("expected one session cookie, got %+v", cookies)
	}
	token := cookies[0].Value

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	if !store.ValidSession(req) {
		t.Fatal("valid session was rejected")
	}

	store.DeleteSession(rec, req)
	if store.ValidSession(req) {
		t.Fatal("session was still valid after deletion")
	}
}

func TestAuthSessionRejectsBogusToken(t *testing.T) {
	cfg := defaultConfig()
	cfg.StateDir = t.TempDir()
	store, err := NewAuthStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "bogus-token"})
	if store.ValidSession(req) {
		t.Fatal("bogus session token was accepted")
	}
}

func TestAuthPersistsAcrossRestart(t *testing.T) {
	stateDir := t.TempDir()
	cfg := defaultConfig()
	cfg.StateDir = stateDir

	store1, err := NewAuthStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store1.Setup("persisted-password"); err != nil {
		t.Fatal(err)
	}

	store2, err := NewAuthStore(Config{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if !store2.Verify("persisted-password") {
		t.Fatal("password should persist across restart")
	}
	if store2.Verify("other-password") {
		t.Fatal("wrong password should not verify after restart")
	}
}

func TestAuthRejectsMangledHash(t *testing.T) {
	stateDir := t.TempDir()
	cfg := defaultConfig()
	cfg.StateDir = stateDir
	store, err := NewAuthStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Setup("real-password"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "web-password.hash"), []byte("not-a-real-hash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store2, err := NewAuthStore(Config{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if store2.Verify("real-password") {
		t.Fatal("mangled hash should not verify")
	}
}

func TestAuthLoginRateLimit(t *testing.T) {
	cfg := defaultConfig()
	cfg.StateDir = t.TempDir()
	store, err := NewAuthStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Setup("rate-limit-password"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for attempt := 1; attempt < loginFailureLimit; attempt++ {
		ok, retryAfter := store.authenticateAt("192.0.2.10", "wrong-password", now)
		if ok || retryAfter != 0 {
			t.Fatalf("attempt %d = %v, %v; want false, 0", attempt, ok, retryAfter)
		}
	}
	ok, retryAfter := store.authenticateAt("192.0.2.10", "wrong-password", now)
	if ok || retryAfter != loginBlockDuration {
		t.Fatalf("blocking attempt = %v, %v; want false, %v", ok, retryAfter, loginBlockDuration)
	}
	if ok, retryAfter := store.authenticateAt("192.0.2.10", "rate-limit-password", now.Add(time.Minute)); ok || retryAfter <= 0 {
		t.Fatalf("blocked client bypassed limit with correct password: %v, %v", ok, retryAfter)
	}
	if ok, retryAfter := store.authenticateAt("192.0.2.11", "rate-limit-password", now.Add(time.Minute)); !ok || retryAfter != 0 {
		t.Fatalf("different client was rate limited: %v, %v", ok, retryAfter)
	}
	if ok, retryAfter := store.authenticateAt("192.0.2.10", "rate-limit-password", now.Add(loginBlockDuration+time.Second)); !ok || retryAfter != 0 {
		t.Fatalf("client did not recover after block duration: %v, %v", ok, retryAfter)
	}
}

func TestLoginRouteReturnsTooManyRequests(t *testing.T) {
	cfg := defaultConfig()
	cfg.StateDir = t.TempDir()
	store, err := NewAuthStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Setup("route-rate-limit-password"); err != nil {
		t.Fatal(err)
	}
	handler := routes(NewManager(cfg), NewExitCatalog(cfg), NewConfigStore("", cfg), store, cfg)
	for attempt := 1; attempt <= loginFailureLimit; attempt++ {
		request := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"password":"wrong-password"}`))
		request.RemoteAddr = "192.0.2.20:45678"
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		wantStatus := http.StatusUnauthorized
		if attempt == loginFailureLimit {
			wantStatus = http.StatusTooManyRequests
			if recorder.Header().Get("Retry-After") == "" {
				t.Fatal("rate-limited response did not include Retry-After")
			}
		}
		if recorder.Code != wantStatus {
			t.Fatalf("attempt %d status = %d, want %d", attempt, recorder.Code, wantStatus)
		}
	}
}
