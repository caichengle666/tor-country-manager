package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

func (m *Manager) ServeProxy(ctx context.Context) error {
	listener, err := net.Listen("tcp", m.cfg.ProxyAddress)
	if err != nil {
		return fmt.Errorf("listen on proxy address: %w", err)
	}
	defer listener.Close()
	go func() { <-ctx.Done(); _ = listener.Close() }()
	for {
		client, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		go m.forward(client)
	}
}

func (m *Manager) forward(client net.Conn) {
	defer client.Close()
	m.mu.RLock()
	active := m.active
	instance := m.instances[active]
	if instance == nil || instance.Status != "running" {
		m.mu.RUnlock()
		return
	}
	port := instance.SocksPort
	m.mu.RUnlock()
	upstream, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(upstream, client) }()
	go func() { defer wg.Done(); _, _ = io.Copy(client, upstream) }()
	wg.Wait()
}
