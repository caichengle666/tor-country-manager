package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type RouteRequest struct {
	Country   string   `json:"country,omitempty"`
	Countries []string `json:"countries,omitempty"`
	Policy    string   `json:"policy,omitempty"`
}

type ClientRoute struct {
	Country        Country `json:"country"`
	Address        string  `json:"socks5_address"`
	Username       string  `json:"socks5_username"`
	Authentication string  `json:"authentication"`
	Status         string  `json:"status"`
	Ready          bool    `json:"ready"`
	ExitIP         string  `json:"exit_ip,omitempty"`
	SelectedIP     string  `json:"selected_ip,omitempty"`
	SelectedNode   string  `json:"selected_node,omitempty"`
	LatencyMS      int     `json:"latency_ms,omitempty"`
}

func (m *Manager) StartCountryProxies(ctx context.Context) {
	m.mu.Lock()
	m.countryProxyCtx = ctx
	m.mu.Unlock()
	go func() {
		<-ctx.Done()
		m.mu.Lock()
		listeners := make([]net.Listener, 0, len(m.countryListeners))
		for _, listener := range m.countryListeners {
			listeners = append(listeners, listener)
		}
		m.countryListeners = make(map[string]net.Listener)
		m.mu.Unlock()
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
}

func (m *Manager) EnsureCountryProxy(code string) (int, error) {
	code = normalizeCode(code)
	port, err := countryPort(m.cfg.CountryProxyPort, code)
	if err != nil {
		return 0, err
	}
	if m.clientAuth.Key() == "" {
		return 0, errors.New("client API key is not configured")
	}
	m.countryListenMu.Lock()
	defer m.countryListenMu.Unlock()
	m.mu.RLock()
	_, exists := m.countryListeners[code]
	ctx := m.countryProxyCtx
	_, known := m.instances[code]
	m.mu.RUnlock()
	if !known {
		return 0, fmt.Errorf("unknown country %q", code)
	}
	if exists {
		return port, nil
	}
	if ctx == nil || ctx.Err() != nil {
		return 0, errors.New("country proxy service is not running")
	}
	address := net.JoinHostPort(m.cfg.CountryProxyHost, strconv.Itoa(port))
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return 0, fmt.Errorf("listen on country proxy %s: %w", address, err)
	}
	m.mu.Lock()
	m.countryListeners[code] = listener
	m.mu.Unlock()
	go m.serveCountryProxy(ctx, code, listener)
	return port, nil
}

func (m *Manager) serveCountryProxy(ctx context.Context, code string, listener net.Listener) {
	go func() { <-ctx.Done(); _ = listener.Close() }()
	for {
		client, err := listener.Accept()
		if err != nil {
			return
		}
		go m.forwardCountry(client, code)
	}
}

func (m *Manager) forwardCountry(client net.Conn, code string) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(15 * time.Second))
	if !negotiateClientAuth(client, code, m.clientAuth.Key()) {
		return
	}
	instance, ok := m.acquireInstance(code)
	if !ok {
		writeSOCKS5Failure(client, 1)
		return
	}
	defer m.releaseInstance(instance)
	internalAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(instance.SocksPort))
	upstream, err := net.DialTimeout("tcp", internalAddress, 5*time.Second)
	if err != nil {
		writeSOCKS5Failure(client, 1)
		return
	}
	defer upstream.Close()
	if _, err := upstream.Write([]byte{5, 1, 0}); err != nil {
		writeSOCKS5Failure(client, 1)
		return
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(upstream, response); err != nil || response[0] != 5 || response[1] != 0 {
		writeSOCKS5Failure(client, 1)
		return
	}
	if _, err := client.Write([]byte{1, 0}); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})
	proxyBothWays(client, upstream)
}

func writeSOCKS5Failure(connection net.Conn, status byte) {
	_, _ = connection.Write([]byte{5, status, 0, 1, 0, 0, 0, 0, 0, 0})
}

func (m *Manager) UpdateClientAPIKey(key string) {
	m.clientAuth.Update(key)
}

func negotiateClientAuth(connection net.Conn, expectedUsername, expectedPassword string) bool {
	header := make([]byte, 2)
	if _, err := io.ReadFull(connection, header); err != nil || header[0] != 5 || header[1] == 0 {
		return false
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(connection, methods); err != nil {
		return false
	}
	supportsPassword := false
	for _, method := range methods {
		if method == 2 {
			supportsPassword = true
			break
		}
	}
	if !supportsPassword {
		_, _ = connection.Write([]byte{5, 0xff})
		return false
	}
	if _, err := connection.Write([]byte{5, 2}); err != nil {
		return false
	}
	if _, err := io.ReadFull(connection, header); err != nil || header[0] != 1 || header[1] == 0 {
		return false
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(connection, username); err != nil {
		return false
	}
	length := make([]byte, 1)
	if _, err := io.ReadFull(connection, length); err != nil || length[0] == 0 {
		return false
	}
	password := make([]byte, int(length[0]))
	if _, err := io.ReadFull(connection, password); err != nil {
		return false
	}
	valid := constantTimeEqual(string(username), expectedUsername) && constantTimeEqual(string(password), expectedPassword)
	if !valid {
		_, _ = connection.Write([]byte{1, 1})
	}
	return valid
}

func constantTimeEqual(value, expected string) bool {
	if len(value) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(value), []byte(expected)) == 1
}

func validBearerToken(request *http.Request, auth *RuntimeClientAuth) bool {
	if auth == nil {
		return false
	}
	value := request.Header.Get("Authorization")
	if !strings.HasPrefix(value, "Bearer ") {
		return false
	}
	return auth.Valid(strings.TrimSpace(strings.TrimPrefix(value, "Bearer ")))
}

func clientRouteForRequest(manager *Manager, cfg Config, request *http.Request, code string) (ClientRoute, error) {
	code = normalizeCode(code)
	instance, ok := manager.Instance(code)
	if !ok {
		return ClientRoute{}, fmt.Errorf("unknown country %q", code)
	}
	port, err := manager.EnsureCountryProxy(code)
	if err != nil {
		return ClientRoute{}, err
	}
	host := publicRouteHost(request.Host, cfg.CountryProxyHost)
	return ClientRoute{
		Country:        instance.Country,
		Address:        net.JoinHostPort(host, strconv.Itoa(port)),
		Username:       code,
		Authentication: "password_is_client_api_key",
		Status:         instance.Status,
		Ready:          instance.Status == "running" || instance.Status == "switching",
		ExitIP:         instance.ExitIP,
		SelectedIP:     instance.SelectedIP,
		SelectedNode:   instance.SelectedNode,
	}, nil
}

func proxyBothWays(first, second net.Conn) {
	var wait sync.WaitGroup
	wait.Add(2)
	go func() { defer wait.Done(); _, _ = io.Copy(second, first) }()
	go func() { defer wait.Done(); _, _ = io.Copy(first, second) }()
	wait.Wait()
}

func publicRouteHost(requestHost, configuredHost string) string {
	if configuredHost != "" && configuredHost != "0.0.0.0" && configuredHost != "::" {
		return configuredHost
	}
	host, _, err := net.SplitHostPort(requestHost)
	if err == nil {
		return host
	}
	return strings.Trim(requestHost, "[]")
}
