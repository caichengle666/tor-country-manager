package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type ConfigStore struct {
	mu   sync.RWMutex
	path string
	cfg  Config
}

type UpstreamSettings struct {
	Address     string `json:"address"`
	Username    string `json:"username"`
	HasPassword bool   `json:"has_password"`
}

type RuntimeSettings struct {
	MaxRunning int `json:"max_running"`
}

type ClientSettings struct {
	Host      string `json:"host"`
	BasePort  int    `json:"base_port"`
	HasAPIKey bool   `json:"has_api_key"`
}

type ClientUpdate struct {
	Host          string  `json:"host"`
	BasePort      int     `json:"base_port"`
	APIKey        *string `json:"api_key,omitempty"`
	ClearAPIKey   bool    `json:"clear_api_key,omitempty"`
	RegenerateKey bool    `json:"regenerate_key,omitempty"`
}

type UpstreamUpdate struct {
	Address       string  `json:"address"`
	Username      string  `json:"username"`
	Password      *string `json:"password,omitempty"`
	ClearPassword bool    `json:"clear_password,omitempty"`
}

func NewConfigStore(path string, stored Config) *ConfigStore {
	return &ConfigStore{path: path, cfg: stored}
}

func (s *ConfigStore) Runtime() RuntimeSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return RuntimeSettings{MaxRunning: s.cfg.MaxRunning}
}

func (s *ConfigStore) UpdateMaxRunning(limit int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.cfg
	next.MaxRunning = limit
	if err := next.validate(); err != nil {
		return err
	}
	if err := s.saveLocked(next); err != nil {
		return err
	}
	s.cfg = next
	return nil
}

func (s *ConfigStore) Upstream() UpstreamSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return UpstreamSettings{Address: s.cfg.UpstreamSOCKS5, Username: s.cfg.UpstreamUsername, HasPassword: s.cfg.UpstreamPassword != ""}
}

func (s *ConfigStore) Client(effectiveHasAPIKey bool) ClientSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return ClientSettings{Host: s.cfg.CountryProxyHost, BasePort: s.cfg.CountryProxyPort, HasAPIKey: effectiveHasAPIKey || s.cfg.ClientAPIKey != ""}
}

func (s *ConfigStore) ClientAPIKey() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.ClientAPIKey
}

func (s *ConfigStore) UpdateClient(update ClientUpdate) (string, error) {
	update.Host = strings.TrimSpace(update.Host)
	providedKey := update.APIKey != nil && strings.TrimSpace(*update.APIKey) != ""
	if (update.RegenerateKey && update.ClearAPIKey) || (providedKey && (update.RegenerateKey || update.ClearAPIKey)) {
		return "", errors.New("choose only one API key action")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.cfg
	next.CountryProxyHost = update.Host
	next.CountryProxyPort = update.BasePort
	generated := ""
	if update.RegenerateKey {
		value := make([]byte, 32)
		if _, err := rand.Read(value); err != nil {
			return "", fmt.Errorf("generate client API key: %w", err)
		}
		generated = base64.RawURLEncoding.EncodeToString(value)
		next.ClientAPIKey = generated
	} else if update.ClearAPIKey {
		next.ClientAPIKey = ""
	} else if providedKey {
		next.ClientAPIKey = strings.TrimSpace(*update.APIKey)
	}
	if err := next.validate(); err != nil {
		return "", err
	}
	if err := s.saveLocked(next); err != nil {
		return "", err
	}
	s.cfg = next
	return generated, nil
}

func (s *ConfigStore) UpdateUpstream(update UpstreamUpdate) error {
	update.Address = strings.TrimSpace(update.Address)
	update.Username = strings.TrimSpace(update.Username)
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.cfg
	next.UpstreamSOCKS5 = update.Address
	next.UpstreamUsername = update.Username
	if update.ClearPassword || update.Address == "" {
		next.UpstreamPassword = ""
	} else if update.Password != nil && *update.Password != "" {
		next.UpstreamPassword = *update.Password
	}
	if update.Address == "" {
		next.UpstreamUsername = ""
	}
	if err := next.validate(); err != nil {
		return err
	}
	if err := s.saveLocked(next); err != nil {
		return err
	}
	s.cfg = next
	return nil
}

func (s *ConfigStore) ClearLegacyAuth() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.AuthToken == "" {
		return nil
	}
	next := s.cfg
	next.AuthToken = ""
	if err := s.saveLocked(next); err != nil {
		return err
	}
	s.cfg = next
	return nil
}

func (s *ConfigStore) saveLocked(cfg Config) error {
	if s.path == "" {
		return errors.New("configuration path is empty")
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return fmt.Errorf("create configuration directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary configuration: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o640); err != nil {
		temporary.Close()
		return fmt.Errorf("set temporary configuration permissions: %w", err)
	}
	if _, err := temporary.Write(append(b, '\n')); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary configuration: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary configuration: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary configuration: %w", err)
	}
	if err := replaceFile(temporaryPath, s.path); err != nil {
		return fmt.Errorf("save configuration: %w", err)
	}
	return nil
}
