package main

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestForwardReturnsWhenNoActiveInstance(t *testing.T) {
	cfg := defaultConfig()
	cfg.StateDir = t.TempDir()
	manager := NewManager(cfg)
	// No instance is active, so acquireInstance returns false
	server, client := net.Pipe()
	defer client.Close()
	manager.forward(server)
	// forward should return immediately; client side should get EOF
	client.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 10)
	n, err := client.Read(buf)
	if err != io.EOF || n != 0 {
		t.Fatalf("expected EOF on client, got %d bytes err=%v", n, err)
	}
}

func TestForwardPipesDataBidirectionally(t *testing.T) {
	// Start a fake upstream listener that echoes back what it receives
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	upstreamPort := upstream.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn) // echo server
	}()

	cfg := defaultConfig()
	cfg.StateDir = t.TempDir()
	manager := NewManager(cfg)
	manager.mu.Lock()
	manager.instances["us"].SocksPort = upstreamPort
	manager.instances["us"].Status = "running"
	manager.active = "us"
	manager.mu.Unlock()

	server, client := net.Pipe()
	defer client.Close()
	go manager.forward(server)
	client.SetDeadline(time.Now().Add(5 * time.Second))

	message := []byte("hello-through-proxy")
	if _, err := client.Write(message); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(message))
	if _, err := io.ReadFull(client, buffer); err != nil {
		t.Fatalf("could not read echoed data: %v", err)
	}
	if !bytes.Equal(buffer, message) {
		t.Fatalf("got %q, want %q", buffer, message)
	}
}

func TestForwardDoesNotConnectToDrainingInstance(t *testing.T) {
	cfg := defaultConfig()
	cfg.StateDir = t.TempDir()
	manager := NewManager(cfg)
	manager.mu.Lock()
	manager.instances["us"].Status = "running"
	manager.instances["us"].draining = true
	manager.active = "us"
	manager.mu.Unlock()

	server, client := net.Pipe()
	defer client.Close()
	manager.forward(server)
	// Should return immediately because instance is draining
	client.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 10)
	n, err := client.Read(buf)
	if err != io.EOF || n != 0 {
		t.Fatalf("expected EOF for draining instance, got %d bytes err=%v", n, err)
	}
}

func TestProxyBothWaysPropagatesHalfClose(t *testing.T) {
	leftClient, leftProxy := tcpPair(t)
	rightProxy, rightClient := tcpPair(t)
	defer leftClient.Close()
	defer rightClient.Close()

	done := make(chan struct{})
	go func() {
		proxyBothWays(leftProxy, rightProxy)
		close(done)
	}()

	if _, err := leftClient.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := leftClient.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := rightClient.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(rightClient)
	if err != nil || string(request) != "request" {
		t.Fatalf("right side read %q, err=%v", request, err)
	}
	if _, err := rightClient.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := rightClient.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := leftClient.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(leftClient)
	if err != nil || string(response) != "response" {
		t.Fatalf("left side read %q, err=%v", response, err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not finish after both sides half-closed")
	}
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		connection, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- connection
	}()
	client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case server := <-accepted:
		return client, server
	case err := <-acceptErr:
		client.Close()
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		client.Close()
		t.Fatal("timed out accepting TCP test connection")
	}
	return nil, nil
}
