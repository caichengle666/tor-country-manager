package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type Country struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

type Config struct {
	ListenAddress    string    `json:"listen_address"`
	ProxyAddress     string    `json:"proxy_address"`
	TorBinary        string    `json:"tor_binary"`
	StateDir         string    `json:"state_dir"`
	GeoIPFile        string    `json:"geoip_file"`
	GeoIPv6File      string    `json:"geoip6_file"`
	BaseSocksPort    int       `json:"base_socks_port"`
	MaxRunning       int       `json:"max_running"`
	AuthToken        string    `json:"auth_token,omitempty"`
	UpstreamSOCKS5   string    `json:"upstream_socks5,omitempty"`
	UpstreamUsername string    `json:"upstream_username,omitempty"`
	UpstreamPassword string    `json:"upstream_password,omitempty"`
	Countries        []Country `json:"countries"`
}

func defaultConfig() Config {
	return Config{
		ListenAddress: "127.0.0.1:8080",
		ProxyAddress:  "127.0.0.1:1080",
		TorBinary:     "/usr/bin/tor",
		StateDir:      "/var/lib/tor-country-manager",
		GeoIPFile:     "/usr/share/tor/geoip",
		GeoIPv6File:   "/usr/share/tor/geoip6",
		BaseSocksPort: 19050,
		MaxRunning:    6,
		Countries: []Country{
			{Code: "us", Name: "美国"},
			{Code: "jp", Name: "日本"},
			{Code: "de", Name: "德国"},
			{Code: "gb", Name: "英国"},
			{Code: "fr", Name: "法国"},
			{Code: "nl", Name: "荷兰"},
			{Code: "ca", Name: "加拿大"},
			{Code: "sg", Name: "新加坡"},
			{Code: "ch", Name: "瑞士"},
			{Code: "se", Name: "瑞典"},
		},
	}
}

func loadConfig(path string) (Config, error) {
	cfg := defaultConfig()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if token := os.Getenv("TOR_MANAGER_TOKEN"); token != "" {
			cfg.AuthToken = token
		}
		return cfg, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if token := os.Getenv("TOR_MANAGER_TOKEN"); token != "" {
		cfg.AuthToken = token
	}
	if proxy := os.Getenv("TOR_UPSTREAM_SOCKS5"); proxy != "" {
		cfg.UpstreamSOCKS5 = proxy
		cfg.UpstreamUsername = os.Getenv("TOR_UPSTREAM_USERNAME")
		cfg.UpstreamPassword = os.Getenv("TOR_UPSTREAM_PASSWORD")
	}
	return cfg, cfg.validate()
}

var countryCodePattern = regexp.MustCompile(`^[a-zA-Z]{2}$`)

func (c Config) validate() error {
	if c.ListenAddress == "" || c.ProxyAddress == "" || c.TorBinary == "" || c.StateDir == "" {
		return errors.New("listen_address, proxy_address, tor_binary and state_dir are required")
	}
	if c.BaseSocksPort < 1024 || c.BaseSocksPort+len(c.Countries) >= 65535 {
		return errors.New("base_socks_port is outside the usable range")
	}
	if c.MaxRunning < 1 || c.MaxRunning > 32 {
		return errors.New("max_running must be between 1 and 32")
	}
	if c.UpstreamSOCKS5 != "" {
		host, portText, err := net.SplitHostPort(c.UpstreamSOCKS5)
		if err != nil || strings.TrimSpace(host) == "" {
			return errors.New("upstream_socks5 must use host:port format")
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return errors.New("upstream_socks5 has an invalid port")
		}
		if strings.ContainsAny(c.UpstreamUsername+c.UpstreamPassword, "\r\n") {
			return errors.New("upstream proxy credentials cannot contain newlines")
		}
	}
	seen := make(map[string]bool)
	for _, country := range c.Countries {
		if !countryCodePattern.MatchString(country.Code) {
			return fmt.Errorf("invalid country code %q", country.Code)
		}
		code := normalizeCode(country.Code)
		if seen[code] {
			return fmt.Errorf("duplicate country code %q", code)
		}
		seen[code] = true
	}
	return nil
}

func writeExampleConfig(path string) error {
	cfg := defaultConfig()
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o640)
}
