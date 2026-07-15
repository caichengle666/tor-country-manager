package main

import (
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

type UpstreamUpdate struct {
	Address       string  `json:"address"`
	Username      string  `json:"username"`
	Password      *string `json:"password,omitempty"`
	ClearPassword bool    `json:"clear_password,omitempty"`
}

func NewConfigStore(path string, cfg Config) *ConfigStore {
	return &ConfigStore{path: path, cfg: cfg}
}

func (s *ConfigStore) Upstream() UpstreamSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return UpstreamSettings{Address: s.cfg.UpstreamSOCKS5, Username: s.cfg.UpstreamUsername, HasPassword: s.cfg.UpstreamPassword != ""}
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
	s.cfg = next
	return s.saveLocked()
}

func (s *ConfigStore) ClearLegacyAuth() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.AuthToken == "" {
		return nil
	}
	s.cfg.AuthToken = ""
	return s.saveLocked()
}

func (s *ConfigStore) saveLocked() error {
	if s.path == "" {
		return errors.New("configuration path is empty")
	}
	b, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return err
	}
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return fmt.Errorf("create configuration directory: %w", err)
	}
	if err := os.WriteFile(s.path, append(b, '\n'), 0o640); err != nil {
		return fmt.Errorf("save configuration: %w", err)
	}
	return nil
}
