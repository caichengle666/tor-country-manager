package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	routeHealthInterval    = 60 * time.Second
	routeHealthTimeout     = 20 * time.Second
	routeHealthFailures    = 3
	routeHealthSwitchDelay = 10 * time.Minute
)

type routeHealthRecord struct {
	LatencyMS               int
	ObservedExitIP          string
	LastChecked             time.Time
	LastSuccess             time.Time
	ConsecutiveFailures     int
	LastError               string
	LastSwitchAt            time.Time
	LastSwitchNode          string
	LastSwitchError         string
	AutomaticSwitchAttempts int
}

type HealthCountry struct {
	Country                 Country   `json:"country"`
	Status                  string    `json:"status"`
	Active                  bool      `json:"active"`
	ExitIP                  string    `json:"exit_ip,omitempty"`
	ObservedExitIP          string    `json:"observed_exit_ip,omitempty"`
	SelectedIP              string    `json:"selected_ip,omitempty"`
	SelectedNode            string    `json:"selected_node,omitempty"`
	ExitFingerprint         string    `json:"exit_fingerprint,omitempty"`
	LatencyMS               int       `json:"latency_ms"`
	NodeTCPLatencyMS        int       `json:"node_tcp_latency_ms"`
	ActiveConnections       int       `json:"active_connections"`
	DrainingConnections     int       `json:"draining_connections,omitempty"`
	LastChecked             time.Time `json:"last_checked,omitempty"`
	LastSuccess             time.Time `json:"last_success,omitempty"`
	ConsecutiveFailures     int       `json:"consecutive_failures"`
	LastError               string    `json:"last_error,omitempty"`
	LastSwitchAt            time.Time `json:"last_switch_at,omitempty"`
	LastSwitchNode          string    `json:"last_switch_node,omitempty"`
	LastSwitchError         string    `json:"last_switch_error,omitempty"`
	AutomaticSwitchAttempts int       `json:"automatic_switch_attempts"`
}

type HealthReport struct {
	Status                string          `json:"status"`
	CheckedAt             time.Time       `json:"checked_at"`
	GlobalFailure         bool            `json:"global_failure"`
	Active                string          `json:"active,omitempty"`
	ProxyAddress          string          `json:"proxy_address"`
	OnlineCountries       int             `json:"online_countries"`
	FailedCountries       int             `json:"failed_countries"`
	CheckIntervalSeconds  int             `json:"check_interval_seconds"`
	FailureThreshold      int             `json:"failure_threshold"`
	SwitchCooldownSeconds int             `json:"switch_cooldown_seconds"`
	Countries             []HealthCountry `json:"countries"`
}

type RouteHealthMonitor struct {
	manager       *Manager
	catalog       *ExitCatalog
	mu            sync.RWMutex
	records       map[string]routeHealthRecord
	globalFailure bool
	interval      time.Duration
	failures      int
	cooldown      time.Duration
	probe         func(context.Context, Instance) (string, time.Duration, error)
	switchNode    func(ExitNode, bool) error
}

type routeProbeResult struct {
	instance Instance
	active   bool
	exitIP   string
	latency  time.Duration
	err      error
}

func NewRouteHealthMonitor(manager *Manager, catalog *ExitCatalog) *RouteHealthMonitor {
	monitor := &RouteHealthMonitor{
		manager:  manager,
		catalog:  catalog,
		records:  make(map[string]routeHealthRecord),
		interval: routeHealthInterval,
		failures: routeHealthFailures,
		cooldown: routeHealthSwitchDelay,
		probe:    probeTorRoute,
	}
	monitor.switchNode = func(node ExitNode, activate bool) error {
		if activate {
			return manager.ActivateNode(node)
		}
		return manager.StartNode(node)
	}
	return monitor
}

func (m *RouteHealthMonitor) Start(ctx context.Context) {
	go func() {
		m.runOnce(ctx)
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.runOnce(ctx)
			}
		}
	}()
}

func (m *RouteHealthMonitor) runOnce(ctx context.Context) {
	state := m.manager.State()
	running := make([]Instance, 0)
	for _, instance := range state.Instances {
		if instance.Status == "running" {
			running = append(running, instance)
		}
	}
	results := make(chan routeProbeResult, len(running))
	var wait sync.WaitGroup
	for _, instance := range running {
		wait.Add(1)
		go func(instance Instance, active bool) {
			defer wait.Done()
			if result, ok := m.probeInstance(ctx, instance, active); ok {
				results <- result
			}
		}(instance, state.Active == instance.Country.Code)
	}
	wait.Wait()
	close(results)
	collected := make([]routeProbeResult, 0, len(running))
	successes := 0
	for result := range results {
		collected = append(collected, result)
		if result.err == nil {
			successes++
		}
	}
	globalFailure := len(collected) > 1 && successes == 0
	m.mu.Lock()
	previousGlobalFailure := m.globalFailure
	m.globalFailure = globalFailure
	m.mu.Unlock()
	if globalFailure != previousGlobalFailure {
		if globalFailure {
			log.Printf("health: all %d checked country routes failed; automatic node switching is paused", len(collected))
		} else {
			log.Printf("health: global route connectivity recovered")
		}
	}
	for _, result := range collected {
		m.applyProbeResult(ctx, result, !globalFailure)
	}
}

func (m *RouteHealthMonitor) checkInstance(ctx context.Context, instance Instance, active bool) {
	result, ok := m.probeInstance(ctx, instance, active)
	if ok {
		m.applyProbeResult(ctx, result, true)
	}
}

func (m *RouteHealthMonitor) probeInstance(ctx context.Context, instance Instance, active bool) (routeProbeResult, bool) {
	checkCtx, cancel := context.WithTimeout(ctx, routeHealthTimeout)
	exitIP, latency, err := m.probe(checkCtx, instance)
	cancel()
	current, ok := m.manager.Instance(instance.Country.Code)
	if !ok || current.Status != "running" || current.SocksPort != instance.SocksPort || current.ExitFingerprint != instance.ExitFingerprint {
		return routeProbeResult{}, false
	}
	return routeProbeResult{instance: instance, active: active, exitIP: exitIP, latency: latency, err: err}, true
}

func (m *RouteHealthMonitor) applyProbeResult(ctx context.Context, result routeProbeResult, allowSwitch bool) {
	instance := result.instance
	now := time.Now()
	if result.err == nil {
		m.mu.Lock()
		record := m.records[instance.Country.Code]
		record.LatencyMS = int(result.latency.Round(time.Millisecond) / time.Millisecond)
		record.ObservedExitIP = result.exitIP
		record.LastChecked = now
		record.LastSuccess = now
		record.ConsecutiveFailures = 0
		record.LastError = ""
		record.LastSwitchError = ""
		m.records[instance.Country.Code] = record
		m.mu.Unlock()
		return
	}

	m.mu.Lock()
	record := m.records[instance.Country.Code]
	record.LastChecked = now
	record.ConsecutiveFailures++
	record.LastError = result.err.Error()
	shouldSwitch := allowSwitch && record.ConsecutiveFailures >= m.failures && (record.LastSwitchAt.IsZero() || now.Sub(record.LastSwitchAt) >= m.cooldown)
	m.records[instance.Country.Code] = record
	m.mu.Unlock()
	if !shouldSwitch {
		return
	}

	refreshCtx, refreshCancel := context.WithTimeout(ctx, 30*time.Second)
	refreshErr := m.catalog.EnsureFresh(refreshCtx)
	refreshCancel()
	if refreshErr != nil {
		m.recordSwitchError(instance.Country.Code, "refresh exit catalog: "+refreshErr.Error())
		return
	}
	node, ok := m.alternateNode(instance)
	if !ok {
		m.recordSwitchError(instance.Country.Code, "no alternate exit node is available in the same country")
		return
	}

	m.mu.Lock()
	record = m.records[instance.Country.Code]
	record.LastSwitchAt = now
	record.LastSwitchNode = node.IP
	record.LastSwitchError = ""
	m.records[instance.Country.Code] = record
	m.mu.Unlock()
	if err := m.switchNode(node, result.active); err != nil {
		m.recordSwitchError(instance.Country.Code, err.Error())
		return
	}
	log.Printf("health: %s failed %d consecutive checks; switching to same-country node %s (%s)", instance.Country.Code, record.ConsecutiveFailures, node.IP, node.Fingerprint)
	m.mu.Lock()
	record = m.records[instance.Country.Code]
	record.ConsecutiveFailures = 0
	record.AutomaticSwitchAttempts++
	m.records[instance.Country.Code] = record
	m.mu.Unlock()
}

func (m *RouteHealthMonitor) alternateNode(instance Instance) (ExitNode, bool) {
	m.catalog.StartLatencyChecks(instance.Country.Code)
	currentFingerprint := strings.ToUpper(instance.ExitFingerprint)
	for _, node := range m.catalog.NodesForCountry(instance.Country.Code) {
		if strings.ToUpper(node.Fingerprint) != currentFingerprint && node.IP != instance.SelectedIP {
			return node, true
		}
	}
	return ExitNode{}, false
}

func (m *RouteHealthMonitor) recordSwitchError(code, message string) {
	m.mu.Lock()
	record := m.records[code]
	record.LastSwitchError = message
	m.records[code] = record
	m.mu.Unlock()
	log.Printf("health: automatic node switch for %s failed: %s", code, message)
}

func (m *RouteHealthMonitor) Report() HealthReport {
	state := m.manager.State()
	report := HealthReport{
		Status:                "idle",
		CheckedAt:             time.Now(),
		Active:                state.Active,
		ProxyAddress:          state.ProxyAddress,
		CheckIntervalSeconds:  int(m.interval / time.Second),
		FailureThreshold:      m.failures,
		SwitchCooldownSeconds: int(m.cooldown / time.Second),
		Countries:             make([]HealthCountry, 0),
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	report.GlobalFailure = m.globalFailure
	degraded := false
	for _, instance := range state.Instances {
		if instance.Status != "running" && instance.Status != "switching" && instance.Status != "error" {
			continue
		}
		record := m.records[instance.Country.Code]
		lastError := record.LastError
		if lastError == "" {
			lastError = instance.Error
		}
		latency := record.LatencyMS
		if record.LastChecked.IsZero() {
			latency = -1
		}
		nodeLatency := -1
		if node, ok := m.catalog.Node(instance.ExitFingerprint); ok {
			nodeLatency = node.LatencyMS
		}
		if instance.Status == "error" {
			report.FailedCountries++
			degraded = true
		} else {
			report.OnlineCountries++
		}
		if record.ConsecutiveFailures > 0 || record.LastSwitchError != "" {
			degraded = true
		}
		report.Countries = append(report.Countries, HealthCountry{
			Country:                 instance.Country,
			Status:                  instance.Status,
			Active:                  state.Active == instance.Country.Code,
			ExitIP:                  instance.ExitIP,
			ObservedExitIP:          record.ObservedExitIP,
			SelectedIP:              instance.SelectedIP,
			SelectedNode:            instance.SelectedNode,
			ExitFingerprint:         instance.ExitFingerprint,
			LatencyMS:               latency,
			NodeTCPLatencyMS:        nodeLatency,
			ActiveConnections:       instance.ActiveConnections,
			DrainingConnections:     instance.DrainingConnections,
			LastChecked:             record.LastChecked,
			LastSuccess:             record.LastSuccess,
			ConsecutiveFailures:     record.ConsecutiveFailures,
			LastError:               lastError,
			LastSwitchAt:            record.LastSwitchAt,
			LastSwitchNode:          record.LastSwitchNode,
			LastSwitchError:         record.LastSwitchError,
			AutomaticSwitchAttempts: record.AutomaticSwitchAttempts,
		})
	}
	if report.OnlineCountries > 0 {
		report.Status = "ok"
	}
	if degraded {
		report.Status = "degraded"
	}
	return report
}

func probeTorRoute(ctx context.Context, instance Instance) (string, time.Duration, error) {
	proxyAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(instance.SocksPort))
	dialer := func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialViaSOCKS5(ctx, proxyAddress, address)
	}
	transport := &http.Transport{DialContext: dialer, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}

	torCheckCtx, torCheckCancel := context.WithTimeout(ctx, 9*time.Second)
	started := time.Now()
	ip, torCheckErr := probeTorProject(torCheckCtx, client)
	torCheckCancel()
	if torCheckErr == nil {
		return ip, time.Since(started), nil
	}
	fallbackCtx, fallbackCancel := context.WithTimeout(ctx, 9*time.Second)
	started = time.Now()
	ip, err := probeIPify(fallbackCtx, client)
	fallbackCancel()
	if err != nil {
		return "", time.Since(started), fmt.Errorf("Tor route check failed: %w", err)
	}
	return ip, time.Since(started), nil
}

func probeTorProject(ctx context.Context, client *http.Client) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://check.torproject.org/api/ip", nil)
	if err != nil {
		return "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Tor check returned HTTP %d", response.StatusCode)
	}
	var result struct {
		IP    string `json:"IP"`
		IsTor bool   `json:"IsTor"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&result); err != nil {
		return "", err
	}
	if !result.IsTor || net.ParseIP(result.IP) == nil {
		return "", errors.New("Tor check did not confirm the route")
	}
	return result.IP, nil
}

func probeIPify(ctx context.Context, client *http.Client) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org?format=json", nil)
	if err != nil {
		return "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fallback check returned HTTP %d", response.StatusCode)
	}
	var result struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&result); err != nil {
		return "", err
	}
	if net.ParseIP(result.IP) == nil {
		return "", errors.New("fallback check returned an invalid IP")
	}
	return result.IP, nil
}
