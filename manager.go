package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Instance struct {
	Country             Country   `json:"country"`
	SocksPort           int       `json:"socks_port"`
	Status              string    `json:"status"`
	ExitIP              string    `json:"exit_ip,omitempty"`
	ExitISP             string    `json:"exit_isp,omitempty"`
	ExitASN             string    `json:"exit_asn,omitempty"`
	ExitCountry         string    `json:"exit_country,omitempty"`
	ExitCountryCode     string    `json:"exit_country_code,omitempty"`
	ExitCity            string    `json:"exit_city,omitempty"`
	SelectedIP          string    `json:"selected_ip,omitempty"`
	SelectedNode        string    `json:"selected_node,omitempty"`
	ExitFingerprint     string    `json:"exit_fingerprint,omitempty"`
	Error               string    `json:"error,omitempty"`
	StartedAt           time.Time `json:"started_at,omitempty"`
	ActiveConnections   int       `json:"active_connections"`
	DrainingConnections int       `json:"draining_connections,omitempty"`
	controlPort         int
	dataDir             string
	cancelRotation      context.CancelFunc
	cmd                 *exec.Cmd
	stopping            bool
	draining            bool
	replacement         bool
}

type Manager struct {
	cfg              Config
	mu               sync.RWMutex
	instances        map[string]*Instance
	allInstances     map[*Instance]struct{}
	active           string
	countryProxyCtx  context.Context
	countryListeners map[string]net.Listener
	countryListenMu  sync.Mutex
	clientAuth       *RuntimeClientAuth
}

func NewManager(cfg Config) *Manager {
	m := &Manager{cfg: cfg, instances: make(map[string]*Instance), allInstances: make(map[*Instance]struct{}), countryListeners: make(map[string]net.Listener), clientAuth: NewRuntimeClientAuth(cfg.ClientAPIKey)}
	for index, country := range cfg.Countries {
		country.Code = normalizeCode(country.Code)
		m.instances[country.Code] = &Instance{
			Country:     country,
			SocksPort:   cfg.BaseSocksPort + index,
			controlPort: cfg.BaseSocksPort + 3000 + index,
			Status:      "stopped",
		}
		m.allInstances[m.instances[country.Code]] = struct{}{}
	}
	return m
}

func normalizeCode(code string) string { return strings.ToLower(strings.TrimSpace(code)) }

func (m *Manager) Start(code string) error {
	code = normalizeCode(code)
	if err := m.makeRoom(code); err != nil {
		return err
	}
	m.mu.Lock()
	instance, ok := m.instances[code]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("unknown country %q", code)
	}
	if instance.Status == "starting" || instance.Status == "connecting" || instance.Status == "running" || instance.Status == "switching" || instance.Status == "draining" {
		m.mu.Unlock()
		return nil
	}
	instanceDir := filepath.Join(m.cfg.StateDir, code)
	dataDir := filepath.Join(instanceDir, "data")
	logDir := filepath.Join(instanceDir, "logs")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		m.mu.Unlock()
		return err
	}
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		m.mu.Unlock()
		return err
	}
	instance.dataDir = dataDir
	torrcPath := filepath.Join(instanceDir, "torrc")
	if err := os.WriteFile(torrcPath, []byte(m.torrc(instance, dataDir, logDir)), 0o600); err != nil {
		m.mu.Unlock()
		return err
	}
	cmd := exec.Command(m.cfg.TorBinary, "-f", torrcPath)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		instance.Status = "error"
		instance.Error = err.Error()
		m.mu.Unlock()
		return fmt.Errorf("start tor: %w", err)
	}
	instance.cmd = cmd
	m.allInstances[instance] = struct{}{}
	instance.Status = "starting"
	instance.Error = ""
	instance.ExitIP = ""
	instance.ExitISP = ""
	instance.ExitASN = ""
	instance.ExitCountry = ""
	instance.ExitCountryCode = ""
	instance.ExitCity = ""
	instance.StartedAt = time.Now()
	instance.stopping = false
	m.mu.Unlock()

	go m.watch(instance, cmd)
	go m.awaitReady(instance, cmd)
	return nil
}

func (m *Manager) makeRoom(target string) error {
	m.mu.RLock()
	running := 0
	var oldest *Instance
	for code, instance := range m.instances {
		if instance.Status != "starting" && instance.Status != "connecting" && instance.Status != "running" && instance.Status != "switching" {
			continue
		}
		if code == target {
			m.mu.RUnlock()
			return nil
		}
		running++
		if code != m.active && (oldest == nil || instance.StartedAt.Before(oldest.StartedAt)) {
			oldest = instance
		}
	}
	if running < m.cfg.MaxRunning {
		m.mu.RUnlock()
		return nil
	}
	if oldest == nil {
		m.mu.RUnlock()
		return fmt.Errorf("maximum of %d running instances reached", m.cfg.MaxRunning)
	}
	code := oldest.Country.Code
	m.mu.RUnlock()
	return m.Stop(code)
}

func (m *Manager) torrc(instance *Instance, dataDir, logDir string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ClientOnly 1\n")
	fmt.Fprintf(&b, "RunAsDaemon 0\n")
	fmt.Fprintf(&b, "SocksPort 127.0.0.1:%d\n", instance.SocksPort)
	fmt.Fprintf(&b, "ControlPort 127.0.0.1:%d\n", instance.controlPort)
	fmt.Fprintf(&b, "CookieAuthentication 1\n")
	fmt.Fprintf(&b, "DataDirectory %s\n", dataDir)
	if instance.ExitFingerprint != "" {
		fmt.Fprintf(&b, "ExitNodes $%s\n", instance.ExitFingerprint)
	} else {
		fmt.Fprintf(&b, "ExitNodes {%s}\n", instance.Country.Code)
	}
	fmt.Fprintf(&b, "StrictNodes 1\n")
	fmt.Fprintf(&b, "AvoidDiskWrites 1\n")
	fmt.Fprintf(&b, "Log notice file %s\n", filepath.Join(logDir, "tor.log"))
	if m.cfg.UpstreamSOCKS5 != "" {
		fmt.Fprintf(&b, "Socks5Proxy %s\n", torrcValue(m.cfg.UpstreamSOCKS5))
		if m.cfg.UpstreamUsername != "" && m.cfg.UpstreamPassword != "" {
			fmt.Fprintf(&b, "Socks5ProxyUsername %s\n", torrcValue(m.cfg.UpstreamUsername))
			fmt.Fprintf(&b, "Socks5ProxyPassword %s\n", torrcValue(m.cfg.UpstreamPassword))
		}
	}
	if m.cfg.GeoIPFile != "" {
		fmt.Fprintf(&b, "GeoIPFile %s\n", m.cfg.GeoIPFile)
	}
	if m.cfg.GeoIPv6File != "" {
		fmt.Fprintf(&b, "GeoIPv6File %s\n", m.cfg.GeoIPv6File)
	}
	return b.String()
}

func (m *Manager) watch(instance *Instance, cmd *exec.Cmd) {
	err := cmd.Wait()
	m.mu.Lock()
	defer m.mu.Unlock()
	if instance.cmd != cmd {
		return
	}
	instance.cmd = nil
	delete(m.allInstances, instance)
	if instance.stopping {
		instance.Status = "stopped"
		instance.Error = ""
	} else {
		instance.Status = "error"
		if err != nil {
			instance.Error = err.Error()
		} else {
			instance.Error = "Tor exited unexpectedly"
		}
	}
	instance.stopping = false
	if current := m.instances[instance.Country.Code]; current == instance && m.active == instance.Country.Code {
		m.active = ""
	}
}

func (m *Manager) awaitReady(instance *Instance, cmd *exec.Cmd) {
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(instance.SocksPort))
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 750*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			m.mu.Lock()
			if instance.cmd == cmd && instance.Status == "starting" {
				instance.Status = "connecting"
			}
			m.mu.Unlock()
			if err := m.applyUpstream(instance, m.upstreamConfig()); err != nil {
				m.mu.Lock()
				if instance.cmd == cmd && instance.Status == "connecting" {
					instance.Status = "error"
					instance.Error = "apply upstream proxy: " + err.Error()
				}
				m.mu.Unlock()
				return
			}
			m.awaitBootstrap(instance, cmd)
			return
		}
		time.Sleep(time.Second)
	}
	m.mu.Lock()
	if instance.cmd == cmd && instance.Status == "starting" {
		instance.Status = "error"
		instance.Error = "Tor did not open its SOCKS port within 90 seconds"
	}
	m.mu.Unlock()
}

func (m *Manager) awaitBootstrap(instance *Instance, cmd *exec.Cmd) {
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		if m.refreshInstanceExitIP(instance) {
			return
		}
		m.mu.RLock()
		stillConnecting := instance.cmd == cmd && instance.Status == "connecting"
		m.mu.RUnlock()
		if !stillConnecting {
			return
		}
		time.Sleep(4 * time.Second)
	}
	m.mu.Lock()
	if instance.cmd == cmd && instance.Status == "connecting" {
		instance.Status = "error"
		instance.Error = "Tor did not obtain a working exit within 3 minutes; the network may block Tor"
	}
	m.mu.Unlock()
}

func (m *Manager) Stop(code string) error {
	code = normalizeCode(code)
	m.mu.Lock()
	instance, ok := m.instances[code]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("unknown country %q", code)
	}
	if instance.cmd == nil || instance.cmd.Process == nil {
		instance.Status = "stopped"
		instance.Error = ""
		m.mu.Unlock()
		return nil
	}
	if instance.draining {
		m.mu.Unlock()
		return nil
	}
	instance.draining = true
	instance.Status = "draining"
	if m.active == code {
		m.active = ""
	}
	m.mu.Unlock()
	go m.drainAndStop(instance)
	return nil
}

func (m *Manager) drainAndStop(instance *Instance) {
	deadline := time.Now().Add(time.Duration(m.cfg.DrainTimeoutSec) * time.Second)
	for time.Now().Before(deadline) {
		m.mu.RLock()
		connections := instance.ActiveConnections
		m.mu.RUnlock()
		if connections == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	m.stopInstance(instance)
}

func (m *Manager) stopInstance(instance *Instance) {
	m.mu.Lock()
	if instance.cancelRotation != nil {
		instance.cancelRotation()
		instance.cancelRotation = nil
	}
	cmd := instance.cmd
	if cmd == nil || cmd.Process == nil {
		instance.Status = "stopped"
		instance.Error = ""
		m.mu.Unlock()
		return
	}
	instance.stopping = true
	instance.draining = true
	instance.Status = "stopping"
	m.mu.Unlock()
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		_ = cmd.Process.Kill()
	}
	go func() {
		time.Sleep(8 * time.Second)
		m.mu.RLock()
		stillRunning := instance.cmd == cmd
		m.mu.RUnlock()
		if stillRunning {
			_ = cmd.Process.Kill()
		}
	}()
}

func (m *Manager) acquireInstance(code string) (*Instance, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	instance := m.instances[normalizeCode(code)]
	if instance == nil || (instance.Status != "running" && instance.Status != "switching") || instance.draining {
		return nil, false
	}
	instance.ActiveConnections++
	return instance, true
}

func (m *Manager) releaseInstance(instance *Instance) {
	m.mu.Lock()
	if instance.ActiveConnections > 0 {
		instance.ActiveConnections--
	}
	m.mu.Unlock()
}

func (m *Manager) Activate(code string) error {
	code = normalizeCode(code)
	if err := m.Start(code); err != nil {
		return err
	}
	m.mu.Lock()
	m.active = code
	m.mu.Unlock()
	return nil
}

func (m *Manager) UpdateMaxRunning(limit int) {
	m.mu.Lock()
	m.cfg.MaxRunning = limit
	running := 0
	candidates := make([]*Instance, 0)
	for code, instance := range m.instances {
		if instance.Status != "starting" && instance.Status != "connecting" && instance.Status != "running" && instance.Status != "switching" {
			continue
		}
		running++
		if code != m.active {
			candidates = append(candidates, instance)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].StartedAt.Before(candidates[j].StartedAt) })
	stopCount := running - limit
	if stopCount < 0 {
		stopCount = 0
	}
	if stopCount > len(candidates) {
		stopCount = len(candidates)
	}
	codes := make([]string, 0, stopCount)
	for index := 0; index < stopCount; index++ {
		codes = append(codes, candidates[index].Country.Code)
	}
	m.mu.Unlock()
	for _, code := range codes {
		_ = m.Stop(code)
	}
}

func (m *Manager) ensureCountry(country Country) (*Instance, error) {
	country.Code = normalizeCode(country.Code)
	if !countryCodePattern.MatchString(country.Code) {
		return nil, fmt.Errorf("invalid country code %q", country.Code)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if instance, ok := m.instances[country.Code]; ok {
		if instance.Country.Name == "" && country.Name != "" {
			instance.Country.Name = country.Name
		}
		return instance, nil
	}
	port := m.cfg.BaseSocksPort + len(m.cfg.Countries)
	if port >= 65535 {
		return nil, errors.New("no internal SOCKS ports remain")
	}
	instance := &Instance{
		Country:     country,
		SocksPort:   port,
		controlPort: m.cfg.BaseSocksPort + 3000 + len(m.cfg.Countries),
		Status:      "stopped",
	}
	m.instances[country.Code] = instance
	m.allInstances[instance] = struct{}{}
	m.cfg.Countries = append(m.cfg.Countries, country)
	return instance, nil
}

func (m *Manager) ActivateNode(node ExitNode) error {
	return m.startNode(node, true)
}

func (m *Manager) StartNode(node ExitNode) error {
	return m.startNode(node, false)
}

func (m *Manager) startNode(node ExitNode, activate bool) error {
	if !fingerprintPattern.MatchString(node.Fingerprint) {
		return errors.New("invalid Tor relay fingerprint")
	}
	instance, err := m.ensureCountry(Country{Code: node.CountryCode, Name: node.CountryName})
	if err != nil {
		return err
	}
	m.mu.RLock()
	alreadyRunning := instance.ExitFingerprint == strings.ToUpper(node.Fingerprint) && instance.Status == "running"
	needsReplacement := instance.cmd != nil && !alreadyRunning
	m.mu.RUnlock()
	if alreadyRunning {
		if activate {
			m.mu.Lock()
			m.active = instance.Country.Code
			m.mu.Unlock()
		}
		return nil
	}
	if needsReplacement {
		return m.replaceNode(instance, node, activate)
	}
	m.mu.Lock()
	instance.ExitFingerprint = strings.ToUpper(node.Fingerprint)
	instance.SelectedIP = node.IP
	instance.SelectedNode = node.Nickname
	m.mu.Unlock()
	if activate {
		return m.Activate(instance.Country.Code)
	}
	return m.Start(instance.Country.Code)
}

func (m *Manager) replaceNode(current *Instance, node ExitNode, activate bool) error {
	replacementPort, err := availableLocalPort()
	if err != nil {
		return err
	}
	replacementControlPort, err := availableLocalPort()
	if err != nil {
		return err
	}
	m.mu.Lock()
	if current.replacement {
		m.mu.Unlock()
		return errors.New("a replacement instance is already starting for this country")
	}
	current.replacement = true
	current.Status = "switching"
	replacement := &Instance{
		Country:         current.Country,
		SocksPort:       replacementPort,
		controlPort:     replacementControlPort,
		Status:          "stopped",
		ExitFingerprint: strings.ToUpper(node.Fingerprint),
		SelectedIP:      node.IP,
		SelectedNode:    node.Nickname,
	}
	m.mu.Unlock()
	if err := m.startDetached(replacement, fmt.Sprintf("replacement-%d", time.Now().UnixNano())); err != nil {
		m.mu.Lock()
		current.replacement = false
		current.Status = "running"
		current.Error = "replacement failed: " + err.Error()
		m.mu.Unlock()
		return err
	}
	go m.completeReplacement(current, replacement, activate)
	return nil
}

func availableLocalPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("allocate replacement SOCKS port: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		return 0, fmt.Errorf("release replacement SOCKS port: %w", err)
	}
	return port, nil
}

func (m *Manager) startDetached(instance *Instance, suffix string) error {
	code := instance.Country.Code
	instanceDir := filepath.Join(m.cfg.StateDir, code+"-"+suffix)
	dataDir := filepath.Join(instanceDir, "data")
	logDir := filepath.Join(instanceDir, "logs")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		return err
	}
	instance.dataDir = dataDir
	torrcPath := filepath.Join(instanceDir, "torrc")
	if err := os.WriteFile(torrcPath, []byte(m.torrc(instance, dataDir, logDir)), 0o600); err != nil {
		return err
	}
	cmd := exec.Command(m.cfg.TorBinary, "-f", torrcPath)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start replacement tor: %w", err)
	}
	instance.cmd = cmd
	instance.Status = "starting"
	instance.StartedAt = time.Now()
	m.mu.Lock()
	m.allInstances[instance] = struct{}{}
	m.mu.Unlock()
	go m.watch(instance, cmd)
	go m.awaitReady(instance, cmd)
	return nil
}

func (m *Manager) completeReplacement(current, replacement *Instance, activate bool) {
	deadline := time.Now().Add(4 * time.Minute)
	for time.Now().Before(deadline) {
		m.mu.RLock()
		status := replacement.Status
		m.mu.RUnlock()
		if status == "running" {
			m.mu.Lock()
			if m.instances[current.Country.Code] != current {
				m.mu.Unlock()
				m.stopInstance(replacement)
				return
			}
			replacement.ActiveConnections = 0
			m.instances[current.Country.Code] = replacement
			if activate {
				m.active = current.Country.Code
			}
			current.replacement = false
			current.draining = true
			current.Status = "draining"
			replacement.DrainingConnections = current.ActiveConnections
			m.mu.Unlock()
			go m.drainInstance(current, replacement)
			return
		}
		if status == "error" || status == "stopped" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	m.mu.Lock()
	current.replacement = false
	current.Status = "running"
	current.Error = "replacement instance did not become ready; old route was preserved"
	m.mu.Unlock()
	m.stopInstance(replacement)
}

func (m *Manager) drainInstance(old, current *Instance) {
	deadline := time.Now().Add(time.Duration(m.cfg.DrainTimeoutSec) * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		current.DrainingConnections = old.ActiveConnections
		connections := old.ActiveConnections
		m.mu.Unlock()
		if connections == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	m.stopInstance(old)
	m.mu.Lock()
	if m.instances[current.Country.Code] == current {
		current.DrainingConnections = 0
	}
	m.mu.Unlock()
}

func (m *Manager) sendNewnym(instance *Instance) {
	response, err := m.controlCommand(instance, "SIGNAL NEWNYM")
	if err != nil {
		log.Printf("circuit rotation: %s: %v", instance.Country.Code, err)
		return
	}
	if strings.HasPrefix(response, "250") {
		log.Printf("circuit rotation: new circuit for %s", instance.Country.Code)
	} else if strings.HasPrefix(response, "514") {
		log.Printf("circuit rotation: rate limited for %s, skipping", instance.Country.Code)
	} else {
		log.Printf("circuit rotation: unexpected response for %s: %s", instance.Country.Code, strings.TrimSpace(response))
	}
}

func (m *Manager) controlCommand(instance *Instance, command string) (string, error) {
	if instance.controlPort == 0 || instance.dataDir == "" {
		return "", errors.New("control port is not ready")
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(instance.controlPort)), 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("connect control port: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	cookie, err := os.ReadFile(filepath.Join(instance.dataDir, "control_auth_cookie"))
	if err != nil {
		return "", fmt.Errorf("read control cookie: %w", err)
	}
	if _, err := fmt.Fprintf(conn, "AUTHENTICATE %x\r\n", cookie); err != nil {
		return "", fmt.Errorf("authenticate control port: %w", err)
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read authentication response: %w", err)
	}
	if !strings.HasPrefix(line, "250") {
		return "", fmt.Errorf("control authentication rejected: %s", strings.TrimSpace(line))
	}
	if _, err := fmt.Fprintf(conn, "%s\r\n", command); err != nil {
		return "", fmt.Errorf("send control command: %w", err)
	}
	line, err = reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read control response: %w", err)
	}
	return line, nil
}

func controlValue(value string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "\"", "\\\"")
	return "\"" + replacer.Replace(value) + "\""
}

func torrcValue(value string) string {
	return controlValue(value)
}

func (m *Manager) UpdateUpstream(cfg Config) error {
	m.mu.RLock()
	instances := make([]*Instance, 0, len(m.instances))
	for _, instance := range m.instances {
		if (instance.Status == "running" || instance.Status == "connecting" || instance.Status == "error") &&
			instance.cmd != nil && instance.cmd.Process != nil && !instance.stopping && !instance.draining {
			instances = append(instances, instance)
		}
	}
	m.mu.RUnlock()

	for _, instance := range instances {
		if err := m.applyUpstream(instance, cfg); err != nil {
			return fmt.Errorf("apply upstream proxy to %s: %w", instance.Country.Code, err)
		}
		if _, err := m.controlCommand(instance, "SIGNAL NEWNYM"); err != nil {
			return fmt.Errorf("rotate circuit for %s: %w", instance.Country.Code, err)
		}
		m.mu.Lock()
		cmd := instance.cmd
		retryBootstrap := instance.Status == "error" && cmd != nil && cmd.Process != nil
		if retryBootstrap {
			instance.Status = "connecting"
			instance.Error = ""
		}
		m.mu.Unlock()
		if retryBootstrap {
			go m.awaitBootstrap(instance, cmd)
		}
	}

	m.mu.Lock()
	m.cfg.UpstreamSOCKS5 = cfg.UpstreamSOCKS5
	m.cfg.UpstreamUsername = cfg.UpstreamUsername
	m.cfg.UpstreamPassword = cfg.UpstreamPassword
	m.mu.Unlock()
	return nil
}

func (m *Manager) upstreamConfig() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

func (m *Manager) applyUpstream(instance *Instance, cfg Config) error {
	command := "RESETCONF Socks5Proxy Socks5ProxyUsername Socks5ProxyPassword"
	if cfg.UpstreamSOCKS5 != "" {
		if cfg.UpstreamUsername == "" {
			response, err := m.controlCommand(instance, "RESETCONF Socks5ProxyUsername Socks5ProxyPassword")
			if err != nil {
				return err
			}
			if !strings.HasPrefix(response, "250") {
				return errors.New(strings.TrimSpace(response))
			}
		}
		command = "SETCONF Socks5Proxy=" + controlValue(cfg.UpstreamSOCKS5)
		if cfg.UpstreamUsername != "" {
			command += " Socks5ProxyUsername=" + controlValue(cfg.UpstreamUsername) +
				" Socks5ProxyPassword=" + controlValue(cfg.UpstreamPassword)
		}
	}
	response, err := m.controlCommand(instance, command)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(response, "250") {
		return errors.New(strings.TrimSpace(response))
	}
	return nil
}

func (m *Manager) startCircuitRotation(instance *Instance) {
	m.mu.RLock()
	minutes := m.cfg.CircuitRotateMinutes
	m.mu.RUnlock()
	if minutes <= 0 {
		return
	}
	m.mu.Lock()
	if instance.cancelRotation != nil {
		instance.cancelRotation()
	}
	ctx, cancel := context.WithCancel(context.Background())
	instance.cancelRotation = cancel
	m.mu.Unlock()
	go func() {
		ticker := time.NewTicker(time.Duration(minutes) * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.mu.RLock()
				status := instance.Status
				m.mu.RUnlock()
				if status != "running" {
					cancel()
					return
				}
				m.sendNewnym(instance)
			}
		}
	}()
}

func (m *Manager) RestartRotations() {
	m.mu.RLock()
	instances := make([]*Instance, 0)
	for _, instance := range m.instances {
		if instance.Status == "running" {
			instances = append(instances, instance)
		}
	}
	m.mu.RUnlock()
	for _, instance := range instances {
		m.startCircuitRotation(instance)
	}
}

func (m *Manager) UpdateCircuitRotateMinutes(minutes int) {
	m.mu.Lock()
	m.cfg.CircuitRotateMinutes = minutes
	m.mu.Unlock()
	m.RestartRotations()
}

func (m *Manager) Instance(code string) (Instance, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	instance, ok := m.instances[normalizeCode(code)]
	if !ok {
		return Instance{}, false
	}
	copy := *instance
	copy.cmd = nil
	return copy, true
}

var fingerprintPattern = regexp.MustCompile(`^[A-Fa-f0-9]{40}$`)

type State struct {
	Active       string     `json:"active"`
	ProxyAddress string     `json:"proxy_address"`
	MaxRunning   int        `json:"max_running"`
	Instances    []Instance `json:"instances"`
}

func (m *Manager) State() State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	state := State{Active: m.active, ProxyAddress: m.cfg.ProxyAddress, MaxRunning: m.cfg.MaxRunning}
	for _, configured := range m.cfg.Countries {
		instance := m.instances[normalizeCode(configured.Code)]
		copy := *instance
		copy.cmd = nil
		state.Instances = append(state.Instances, copy)
	}
	return state
}

func (m *Manager) Shutdown() {
	m.mu.RLock()
	instances := make([]*Instance, 0, len(m.allInstances))
	for instance := range m.allInstances {
		if instance.cmd != nil {
			instances = append(instances, instance)
		}
	}
	m.mu.RUnlock()
	for _, instance := range instances {
		m.stopInstance(instance)
	}
}

func (m *Manager) refreshInstanceExitIP(instance *Instance) bool {
	m.mu.RLock()
	port := instance.SocksPort
	m.mu.RUnlock()

	dialer := func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialViaSOCKS5(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), address)
	}
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext:     dialer,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	resp, err := client.Get("https://check.torproject.org/api/ip")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var result struct {
		IP    string `json:"IP"`
		IsTor bool   `json:"IsTor"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&result); err != nil || !result.IsTor {
		return false
	}
	m.mu.Lock()
	instance.ExitIP = result.IP
	instance.Status = "running"
	instance.Error = ""
	m.mu.Unlock()
	m.startCircuitRotation(instance)
	m.lookupExitInfo(client, instance, result.IP)
	return true
}

func (m *Manager) lookupExitInfo(client *http.Client, instance *Instance, ip string) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return
	}
	var info exitInfo
	var ok bool
	for attempt := 0; attempt < 3; attempt++ {
		info, ok = queryIPAPI(client, parsedIP.String())
		if !ok {
			info, ok = queryIPWho(client, parsedIP.String())
		}
		if ok {
			break
		}
		if attempt < 2 {
			time.Sleep(3 * time.Second)
		}
	}
	if !ok {
		return
	}
	m.mu.Lock()
	if instance.ExitIP == ip {
		instance.ExitISP = info.Org
		instance.ExitASN = info.ASN
		instance.ExitCountry = info.CountryName
		instance.ExitCountryCode = info.CountryCode
		instance.ExitCity = info.City
	}
	m.mu.Unlock()
}

type exitInfo struct {
	ASN         string
	Org         string
	CountryName string
	CountryCode string
	City        string
}

func queryIPAPI(client *http.Client, ip string) (exitInfo, bool) {
	resp, err := client.Get("https://ipapi.co/" + ip + "/json/")
	if err != nil {
		return exitInfo{}, false
	}
	defer resp.Body.Close()
	var result struct {
		Error       bool   `json:"error"`
		ASN         string `json:"asn"`
		Org         string `json:"org"`
		CountryName string `json:"country_name"`
		CountryCode string `json:"country_code"`
		City        string `json:"city"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&result) != nil || result.Error {
		return exitInfo{}, false
	}
	return exitInfo{ASN: result.ASN, Org: result.Org, CountryName: result.CountryName, CountryCode: result.CountryCode, City: result.City}, result.Org != "" || result.ASN != ""
}

func queryIPWho(client *http.Client, ip string) (exitInfo, bool) {
	resp, err := client.Get("https://ipwho.is/" + ip)
	if err != nil {
		return exitInfo{}, false
	}
	defer resp.Body.Close()
	var result struct {
		Success     bool   `json:"success"`
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
		City        string `json:"city"`
		Connection  struct {
			ASN int    `json:"asn"`
			Org string `json:"org"`
			ISP string `json:"isp"`
		} `json:"connection"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&result) != nil || !result.Success {
		return exitInfo{}, false
	}
	org := result.Connection.ISP
	if org == "" {
		org = result.Connection.Org
	}
	asn := ""
	if result.Connection.ASN > 0 {
		asn = fmt.Sprintf("AS%d", result.Connection.ASN)
	}
	return exitInfo{ASN: asn, Org: org, CountryName: result.Country, CountryCode: result.CountryCode, City: result.City}, org != "" || asn != ""
}

func dialViaSOCKS5(ctx context.Context, proxyAddress, targetAddress string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", proxyAddress)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) { _ = conn.Close(); return nil, err }
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil || response[0] != 5 || response[1] != 0 {
		if err == nil {
			err = errors.New("SOCKS5 authentication negotiation failed")
		}
		return fail(err)
	}
	host, portText, err := net.SplitHostPort(targetAddress)
	if err != nil {
		return fail(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fail(errors.New("invalid target port"))
	}
	if len(host) > 255 {
		return fail(errors.New("target hostname is too long"))
	}
	request := []byte{5, 1, 0, 3, byte(len(host))}
	request = append(request, host...)
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err := conn.Write(request); err != nil {
		return fail(err)
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fail(err)
	}
	if header[1] != 0 {
		return fail(fmt.Errorf("SOCKS5 proxy returned status %d", header[1]))
	}
	var addressLength int
	switch header[3] {
	case 1:
		addressLength = 4
	case 3:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return fail(err)
		}
		addressLength = int(length[0])
	case 4:
		addressLength = 16
	default:
		return fail(errors.New("SOCKS5 proxy returned an unknown address type"))
	}
	if _, err := io.CopyN(io.Discard, conn, int64(addressLength+2)); err != nil {
		return fail(err)
	}
	return conn, nil
}

func tailFile(path string, lines int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	buffer := make([]string, 0, lines)
	for scanner.Scan() {
		if len(buffer) == lines {
			copy(buffer, buffer[1:])
			buffer = buffer[:lines-1]
		}
		buffer = append(buffer, scanner.Text())
	}
	return strings.Join(buffer, "\n"), scanner.Err()
}
