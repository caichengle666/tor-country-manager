package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBearerTokenAuthentication(t *testing.T) {
	request := httptest.NewRequest("GET", "/api/v1/countries", nil)
	request.Header.Set("Authorization", "Bearer secret-value")
	auth := NewRuntimeClientAuth("secret-value")
	if !validBearerToken(request, auth) {
		t.Fatal("valid Bearer token was rejected")
	}
	auth.Update("different-value")
	if validBearerToken(request, auth) {
		t.Fatal("invalid Bearer token was accepted")
	}
}

func TestCountryProxyForwardsCONNECTToTor(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	upstreamPort := upstream.Addr().(*net.TCPAddr).Port
	connectRequest := []byte{5, 1, 0, 3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 1, 187}
	upstreamDone := make(chan error, 1)
	go func() {
		connection, err := upstream.Accept()
		if err != nil {
			upstreamDone <- err
			return
		}
		defer connection.Close()
		greeting := make([]byte, 3)
		if _, err := io.ReadFull(connection, greeting); err != nil {
			upstreamDone <- err
			return
		}
		if !bytes.Equal(greeting, []byte{5, 1, 0}) {
			upstreamDone <- fmt.Errorf("unexpected Tor greeting %v", greeting)
			return
		}
		if _, err := connection.Write([]byte{5, 0}); err != nil {
			upstreamDone <- err
			return
		}
		request := make([]byte, len(connectRequest))
		if _, err := io.ReadFull(connection, request); err != nil {
			upstreamDone <- err
			return
		}
		if !bytes.Equal(request, connectRequest) {
			upstreamDone <- fmt.Errorf("CONNECT changed in transit: %v", request)
			return
		}
		_, err = connection.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 4, 56})
		upstreamDone <- err
	}()

	cfg := defaultConfig()
	cfg.ClientAPIKey = "test-client-secret"
	manager := NewManager(cfg)
	manager.mu.Lock()
	manager.instances["us"].SocksPort = upstreamPort
	manager.instances["us"].Status = "running"
	manager.mu.Unlock()
	server, client := net.Pipe()
	defer client.Close()
	go manager.forwardCountry(server, "us")
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(client, response); err != nil || !bytes.Equal(response, []byte{5, 2}) {
		t.Fatalf("method response %v: %v", response, err)
	}
	auth := append([]byte{1, 2, 'u', 's', byte(len(cfg.ClientAPIKey))}, []byte(cfg.ClientAPIKey)...)
	if _, err := client.Write(auth); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, response); err != nil || !bytes.Equal(response, []byte{1, 0}) {
		t.Fatalf("auth response %v: %v", response, err)
	}
	if _, err := client.Write(connectRequest); err != nil {
		t.Fatal(err)
	}
	connectResponse := make([]byte, 10)
	if _, err := io.ReadFull(client, connectResponse); err != nil || connectResponse[1] != 0 {
		t.Fatalf("CONNECT response %v: %v", connectResponse, err)
	}
	if err := <-upstreamDone; err != nil {
		t.Fatal(err)
	}
}

func TestCountrySOCKSAuthentication(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	result := make(chan bool, 1)
	go func() {
		defer server.Close()
		result <- negotiateClientAuth(server, "us", "secret-value")
	}()
	if _, err := client.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(client, response); err != nil || response[1] != 2 {
		t.Fatalf("SOCKS authentication method was not accepted: %v %v", response, err)
	}
	request := []byte{1, 2, 'u', 's', 12}
	request = append(request, []byte("secret-value")...)
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	if !<-result {
		t.Fatal("valid SOCKS credentials were rejected")
	}
}

func TestBestCandidateUsesLowestLatencyAcrossCountries(t *testing.T) {
	catalog := NewExitCatalog(defaultConfig())
	catalog.nodes = map[string]ExitNode{
		"US": {Fingerprint: "US", CountryCode: "us", LatencyMS: 80, ConsensusWeight: 100},
		"JP": {Fingerprint: "JP", CountryCode: "jp", LatencyMS: 30, ConsensusWeight: 10},
	}
	node, ok := catalog.bestCandidate([]string{"us", "jp"}, "lowest_latency", true)
	if !ok || node.CountryCode != "jp" {
		t.Fatalf("selected %+v, want Japanese node", node)
	}
	node, ok = catalog.bestCandidate([]string{"us", "jp"}, "failover", true)
	if !ok || node.CountryCode != "us" {
		t.Fatalf("selected %+v, want first failover country", node)
	}
}
