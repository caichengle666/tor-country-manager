package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestDialSOCKS5WithoutAuthentication(t *testing.T) {
	address, done := startTestSOCKS5Server(t, false)
	connection, err := dialViaSOCKS5(context.Background(), address, "example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDialSOCKS5WithAuthentication(t *testing.T) {
	address, done := startTestSOCKS5Server(t, true)
	connection, err := dialViaUpstreamSOCKS5(context.Background(), address, "example.test:443", "user", "pass")
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func startTestSOCKS5Server(t *testing.T, requireAuth bool) (string, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		defer listener.Close()
		connection, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		done <- handleTestSOCKS5(connection, requireAuth)
	}()
	return listener.Addr().String(), done
}

func handleTestSOCKS5(connection net.Conn, requireAuth bool) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(connection, header); err != nil {
		return err
	}
	methods := make([]byte, int(header[1]))
	if header[0] != 5 {
		return fmt.Errorf("unexpected SOCKS version %d", header[0])
	}
	if _, err := io.ReadFull(connection, methods); err != nil {
		return err
	}
	method := byte(0)
	if requireAuth {
		method = 2
	}
	if _, err := connection.Write([]byte{5, method}); err != nil {
		return err
	}
	if requireAuth {
		if _, err := io.ReadFull(connection, header); err != nil || header[0] != 1 {
			return fmt.Errorf("read auth header: %w", err)
		}
		username := make([]byte, int(header[1]))
		if _, err := io.ReadFull(connection, username); err != nil {
			return err
		}
		length := make([]byte, 1)
		if _, err := io.ReadFull(connection, length); err != nil {
			return err
		}
		password := make([]byte, int(length[0]))
		if _, err := io.ReadFull(connection, password); err != nil {
			return err
		}
		if string(username) != "user" || string(password) != "pass" {
			return fmt.Errorf("unexpected credentials %q:%q", username, password)
		}
		if _, err := connection.Write([]byte{1, 0}); err != nil {
			return err
		}
	}
	request := make([]byte, 5)
	if _, err := io.ReadFull(connection, request); err != nil {
		return err
	}
	if request[0] != 5 || request[1] != 1 || request[3] != 3 {
		return fmt.Errorf("unexpected CONNECT request %v", request)
	}
	target := make([]byte, int(request[4])+2)
	if _, err := io.ReadFull(connection, target); err != nil {
		return err
	}
	if string(target[:len(target)-2]) != "example.test" || target[len(target)-2] != 1 || target[len(target)-1] != 187 {
		return fmt.Errorf("unexpected target %v", target)
	}
	_, err := connection.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
	return err
}
