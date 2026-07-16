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
	CountryProxyHost string    `json:"country_proxy_host"`
	CountryProxyPort int       `json:"country_proxy_base_port"`
	MaxRunning       int       `json:"max_running"`
	AuthToken        string    `json:"auth_token,omitempty"`
	ClientAPIKey     string    `json:"client_api_key,omitempty"`
	UpstreamSOCKS5   string    `json:"upstream_socks5,omitempty"`
	UpstreamUsername string    `json:"upstream_username,omitempty"`
	UpstreamPassword string    `json:"upstream_password,omitempty"`
	Countries        []Country `json:"countries"`
}

type LoadedConfig struct {
	Stored    Config
	Effective Config
}

func defaultConfig() Config {
	return Config{
		ListenAddress:    "127.0.0.1:8080",
		ProxyAddress:     "127.0.0.1:1080",
		TorBinary:        "/usr/bin/tor",
		StateDir:         "/var/lib/tor-country-manager",
		GeoIPFile:        "/usr/share/tor/geoip",
		GeoIPv6File:      "/usr/share/tor/geoip6",
		BaseSocksPort:    19050,
		CountryProxyHost: "127.0.0.1",
		CountryProxyPort: 20000,
		MaxRunning:       10,
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

func loadConfig(path string) (LoadedConfig, error) {
	stored := defaultConfig()
	b, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(b, &stored); err != nil {
			return LoadedConfig{}, fmt.Errorf("parse config: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return LoadedConfig{}, fmt.Errorf("read config: %w", err)
	}

	effective := stored
	if token := os.Getenv("TOR_MANAGER_TOKEN"); token != "" {
		effective.AuthToken = token
	}
	if key := os.Getenv("TOR_CLIENT_API_KEY"); key != "" {
		effective.ClientAPIKey = key
	}
	if proxy := os.Getenv("TOR_UPSTREAM_SOCKS5"); proxy != "" {
		effective.UpstreamSOCKS5 = proxy
		effective.UpstreamUsername = os.Getenv("TOR_UPSTREAM_USERNAME")
		effective.UpstreamPassword = os.Getenv("TOR_UPSTREAM_PASSWORD")
	}
	if err := effective.validate(); err != nil {
		return LoadedConfig{}, err
	}
	return LoadedConfig{Stored: stored, Effective: effective}, nil
}

var countryCodePattern = regexp.MustCompile(`^[a-zA-Z]{2}$`)
var proxyHostPattern = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)

func rangesOverlap(firstStart, firstEnd, secondStart, secondEnd int) bool {
	return firstStart <= secondEnd && secondStart <= firstEnd
}

func countryPort(base int, code string) (int, error) {
	code = normalizeCode(code)
	if !countryCodePattern.MatchString(code) {
		return 0, fmt.Errorf("invalid country code %q", code)
	}
	index := int(code[0]-'a')*26 + int(code[1]-'a')
	return base + index, nil
}

func (c Config) validate() error {
	if c.ListenAddress == "" || c.ProxyAddress == "" || c.TorBinary == "" || c.StateDir == "" {
		return errors.New("listen_address, proxy_address, tor_binary and state_dir are required")
	}
	if c.BaseSocksPort < 1024 || c.BaseSocksPort+675 >= 65535 {
		return errors.New("base_socks_port is outside the usable range")
	}
	proxyHost := strings.TrimSpace(c.CountryProxyHost)
	if proxyHost == "" || (net.ParseIP(proxyHost) == nil && !proxyHostPattern.MatchString(proxyHost)) {
		return errors.New("country_proxy_host must be an IP address or hostname without a port")
	}
	if c.CountryProxyPort < 1024 || c.CountryProxyPort+675 >= 65535 {
		return errors.New("country_proxy_base_port is outside the usable range")
	}
	if rangesOverlap(c.BaseSocksPort, c.BaseSocksPort+675, c.CountryProxyPort, c.CountryProxyPort+675) {
		return errors.New("internal and country proxy port ranges overlap")
	}
	if strings.ContainsAny(c.ClientAPIKey, "\r\n") {
		return errors.New("client API key cannot contain newlines")
	}
	if c.ClientAPIKey != "" && (len(c.ClientAPIKey) < 16 || len(c.ClientAPIKey) > 255) {
		return errors.New("client API key must be between 16 and 255 characters")
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
