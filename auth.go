package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	passwordIterations  = 210000
	sessionCookieName   = "tor_manager_session"
	sessionLifetime     = 12 * time.Hour
	loginFailureLimit   = 5
	loginBlockDuration  = 5 * time.Minute
	loginRecordLifetime = 15 * time.Minute
)

type loginAttempt struct {
	Failures     int
	BlockedUntil time.Time
	LastSeen     time.Time
}

type AuthStore struct {
	mu            sync.RWMutex
	hashPath      string
	legacy        string
	hash          string
	sessions      map[string]time.Time
	loginAttempts map[string]loginAttempt
}

func NewAuthStore(cfg Config) (*AuthStore, error) {
	store := &AuthStore{
		hashPath:      filepath.Join(cfg.StateDir, "web-password.hash"),
		legacy:        cfg.AuthToken,
		sessions:      make(map[string]time.Time),
		loginAttempts: make(map[string]loginAttempt),
	}
	b, err := os.ReadFile(store.hashPath)
	if err == nil {
		store.hash = strings.TrimSpace(string(b))
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read web password: %w", err)
	}
	return store, nil
}

func (a *AuthStore) Configured() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.hash != "" || a.legacy != ""
}

func (a *AuthStore) Setup(password string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.hash != "" || a.legacy != "" {
		return errors.New("administrator password is already configured")
	}
	return a.setPasswordLocked(password)
}

func (a *AuthStore) Change(current, replacement string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.verifyLocked(current) {
		return errors.New("current administrator password is incorrect")
	}
	if err := a.setPasswordLocked(replacement); err != nil {
		return err
	}
	a.legacy = ""
	a.sessions = make(map[string]time.Time)
	return nil
}

func (a *AuthStore) setPasswordLocked(password string) error {
	if len(password) < 8 {
		return errors.New("administrator password must contain at least 8 characters")
	}
	if len(password) > 256 {
		return errors.New("administrator password is too long")
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.hashPath), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(a.hashPath, []byte(hash+"\n"), 0o600); err != nil {
		return fmt.Errorf("save web password: %w", err)
	}
	a.hash = hash
	return nil
}

func (a *AuthStore) Authenticate(client, password string) (bool, time.Duration) {
	return a.authenticateAt(client, password, time.Now())
}

func (a *AuthStore) authenticateAt(client, password string, now time.Time) (bool, time.Duration) {
	if client == "" {
		client = "unknown"
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for key, attempt := range a.loginAttempts {
		if now.Sub(attempt.LastSeen) > loginRecordLifetime {
			delete(a.loginAttempts, key)
		}
	}
	attempt := a.loginAttempts[client]
	if now.Before(attempt.BlockedUntil) {
		attempt.LastSeen = now
		a.loginAttempts[client] = attempt
		return false, attempt.BlockedUntil.Sub(now)
	}
	if a.verifyLocked(password) {
		delete(a.loginAttempts, client)
		return true, 0
	}
	attempt.Failures++
	attempt.LastSeen = now
	if attempt.Failures >= loginFailureLimit {
		attempt.Failures = 0
		attempt.BlockedUntil = now.Add(loginBlockDuration)
	}
	a.loginAttempts[client] = attempt
	if now.Before(attempt.BlockedUntil) {
		return false, attempt.BlockedUntil.Sub(now)
	}
	return false, 0
}

func (a *AuthStore) verifyLocked(password string) bool {
	if a.hash != "" {
		return verifyPassword(a.hash, password)
	}
	if a.legacy != "" {
		return subtle.ConstantTimeCompare([]byte(a.legacy), []byte(password)) == 1
	}
	return false
}

func (a *AuthStore) CreateSession(w http.ResponseWriter) error {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return err
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	a.mu.Lock()
	a.sessions[token] = time.Now().Add(sessionLifetime)
	for existing, expires := range a.sessions {
		if time.Now().After(expires) {
			delete(a.sessions, existing)
		}
	}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionLifetime.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func (a *AuthStore) ValidSession(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	a.mu.RLock()
	expires, ok := a.sessions[cookie.Value]
	a.mu.RUnlock()
	return ok && time.Now().Before(expires)
}

func (a *AuthStore) DeleteSession(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		a.mu.Lock()
		delete(a.sessions, cookie.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := pbkdf2SHA256([]byte(password), salt, passwordIterations)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", passwordIterations, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func verifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 100000 || iterations > 1000000 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) < 16 {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(expected) != sha256.Size {
		return false
	}
	actual := pbkdf2SHA256([]byte(password), salt, iterations)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func pbkdf2SHA256(password, salt []byte, iterations int) []byte {
	block := make([]byte, len(salt)+4)
	copy(block, salt)
	binary.BigEndian.PutUint32(block[len(salt):], 1)
	mac := hmac.New(sha256.New, password)
	_, _ = mac.Write(block)
	u := mac.Sum(nil)
	result := append([]byte(nil), u...)
	for round := 1; round < iterations; round++ {
		mac.Reset()
		_, _ = mac.Write(u)
		u = mac.Sum(nil)
		for index := range result {
			result[index] ^= u[index]
		}
	}
	return result
}
