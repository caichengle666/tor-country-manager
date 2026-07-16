package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
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
