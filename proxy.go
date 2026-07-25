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
	m.mu.RUnlock()
	instance, ok := m.acquireInstance(active)
	if !ok {
		return
	}
	defer m.releaseInstance(instance)
	port := instance.SocksPort
	upstream, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	proxyBothWays(client, upstream)
}

func proxyBothWays(first, second net.Conn) {
	var wait sync.WaitGroup
	wait.Add(2)
	go proxyCopy(second, first, &wait)
	go proxyCopy(first, second, &wait)
	wait.Wait()
}

func proxyCopy(destination, source net.Conn, wait *sync.WaitGroup) {
	defer wait.Done()
	_, _ = io.Copy(destination, source)
	if connection, ok := destination.(interface{ CloseWrite() error }); ok {
		_ = connection.CloseWrite()
	} else {
		_ = destination.Close()
	}
}
