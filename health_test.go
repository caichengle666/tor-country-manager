package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHealthReportIncludesOnlineCountryAndLatencies(t *testing.T) {
	cfg := defaultConfig()
	cfg.StateDir = t.TempDir()
	manager := NewManager(cfg)
	fingerprint := strings.Repeat("A", 40)
	manager.mu.Lock()
	instance := manager.instances["us"]
	instance.Status = "running"
	instance.ExitIP = "198.51.100.10"
	instance.SelectedIP = "198.51.100.20"
	instance.SelectedNode = "test-exit"
	instance.ExitFingerprint = fingerprint
	instance.ActiveConnections = 2
	manager.active = "us"
	manager.mu.Unlock()

	catalog := NewExitCatalog(cfg)
	catalog.mu.Lock()
	catalog.nodes[fingerprint] = ExitNode{Fingerprint: fingerprint, CountryCode: "us", IP: "198.51.100.20", LatencyMS: 47}
	catalog.fetchedAt = time.Now()
	catalog.mu.Unlock()
	monitor := NewRouteHealthMonitor(manager, catalog)
	now := time.Now()
	monitor.records["us"] = routeHealthRecord{LatencyMS: 312, ObservedExitIP: "198.51.100.10", LastChecked: now, LastSuccess: now}

	report := monitor.Report()
	if report.Status != "ok" || report.OnlineCountries != 1 || report.Active != "us" {
		t.Fatalf("unexpected health summary: %+v", report)
	}
	country := report.Countries[0]
	if country.Country.Code != "us" || !country.Active || country.LatencyMS != 312 || country.NodeTCPLatencyMS != 47 || country.ActiveConnections != 2 {
		t.Fatalf("unexpected country health: %+v", country)
	}
}

func TestHealthMonitorSwitchesToAlternateNodeAfterThreshold(t *testing.T) {
	cfg := defaultConfig()
	cfg.StateDir = t.TempDir()
	manager := NewManager(cfg)
	currentFingerprint := strings.Repeat("A", 40)
	alternateFingerprint := strings.Repeat("B", 40)
	manager.mu.Lock()
	instance := manager.instances["us"]
	instance.Status = "running"
	instance.ExitFingerprint = currentFingerprint
	instance.SelectedIP = "198.51.100.10"
	manager.active = "us"
	copy := *instance
	manager.mu.Unlock()

	catalog := NewExitCatalog(cfg)
	catalog.mu.Lock()
	catalog.nodes[currentFingerprint] = ExitNode{Fingerprint: currentFingerprint, CountryCode: "us", IP: "198.51.100.10", LatencyMS: 20}
	catalog.nodes[alternateFingerprint] = ExitNode{Fingerprint: alternateFingerprint, CountryCode: "us", CountryName: "United States", IP: "198.51.100.11", LatencyMS: 30}
	catalog.fetchedAt = time.Now()
	catalog.mu.Unlock()

	monitor := NewRouteHealthMonitor(manager, catalog)
	monitor.probe = func(context.Context, Instance) (string, time.Duration, error) {
		return "", time.Second, errors.New("route unavailable")
	}
	var selected ExitNode
	activated := false
	monitor.switchNode = func(node ExitNode, active bool) error {
		selected = node
		activated = active
		return nil
	}
	for attempt := 0; attempt < routeHealthFailures; attempt++ {
		monitor.checkInstance(context.Background(), copy, true)
	}
	if selected.Fingerprint != alternateFingerprint || !activated {
		t.Fatalf("automatic switch selected %+v, active=%v", selected, activated)
	}
	record := monitor.records["us"]
	if record.AutomaticSwitchAttempts != 1 || record.ConsecutiveFailures != 0 || record.LastSwitchNode != "198.51.100.11" {
		t.Fatalf("unexpected switch record: %+v", record)
	}
	for attempt := 0; attempt < routeHealthFailures; attempt++ {
		monitor.checkInstance(context.Background(), copy, true)
	}
	if record = monitor.records["us"]; record.AutomaticSwitchAttempts != 1 {
		t.Fatalf("switch cooldown allowed another attempt: %+v", record)
	}
}

func TestHealthMonitorSuppressesSwitchDuringGlobalFailure(t *testing.T) {
	cfg := defaultConfig()
	cfg.StateDir = t.TempDir()
	manager := NewManager(cfg)
	manager.mu.Lock()
	for _, code := range []string{"us", "jp"} {
		instance := manager.instances[code]
		instance.Status = "running"
		instance.ExitFingerprint = strings.Repeat(strings.ToUpper(code[:1]), 40)
	}
	manager.mu.Unlock()

	catalog := NewExitCatalog(cfg)
	catalog.mu.Lock()
	catalog.nodes[strings.Repeat("C", 40)] = ExitNode{Fingerprint: strings.Repeat("C", 40), CountryCode: "us", IP: "198.51.100.30"}
	catalog.nodes[strings.Repeat("D", 40)] = ExitNode{Fingerprint: strings.Repeat("D", 40), CountryCode: "jp", IP: "198.51.100.31"}
	catalog.fetchedAt = time.Now()
	catalog.mu.Unlock()

	monitor := NewRouteHealthMonitor(manager, catalog)
	monitor.failures = 1
	monitor.probe = func(context.Context, Instance) (string, time.Duration, error) {
		return "", time.Second, errors.New("upstream unavailable")
	}
	switches := 0
	monitor.switchNode = func(ExitNode, bool) error {
		switches++
		return nil
	}
	monitor.runOnce(context.Background())
	if switches != 0 || !monitor.Report().GlobalFailure {
		t.Fatalf("global failure triggered %d switches, report=%+v", switches, monitor.Report())
	}
}

func TestHealthReportIncludesFailedCountry(t *testing.T) {
	cfg := defaultConfig()
	cfg.StateDir = t.TempDir()
	manager := NewManager(cfg)
	manager.mu.Lock()
	instance := manager.instances["jp"]
	instance.Status = "error"
	instance.Error = "automatic restart limit reached after 3 attempts"
	manager.mu.Unlock()

	monitor := NewRouteHealthMonitor(manager, NewExitCatalog(cfg))
	report := monitor.Report()
	if report.Status != "degraded" || report.OnlineCountries != 0 || report.FailedCountries != 1 || len(report.Countries) != 1 {
		t.Fatalf("unexpected failed-country summary: %+v", report)
	}
	if report.Countries[0].Country.Code != "jp" || report.Countries[0].Status != "error" || !strings.Contains(report.Countries[0].LastError, "restart limit") {
		t.Fatalf("failed country was not preserved: %+v", report.Countries[0])
	}
}

func TestHealthEndpointIsPublic(t *testing.T) {
	cfg := defaultConfig()
	cfg.StateDir = t.TempDir()
	manager := NewManager(cfg)
	catalog := NewExitCatalog(cfg)
	monitor := NewRouteHealthMonitor(manager, catalog)
	authStore, err := NewAuthStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	handler := routes(manager, catalog, monitor, NewConfigStore(filepath.Join(t.TempDir(), "config.json"), cfg), authStore, cfg)
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"online_countries":0`) || !strings.Contains(response.Body.String(), `"countries":[]`) {
		t.Fatalf("health endpoint returned %d: %s", response.Code, response.Body.String())
	}
}
