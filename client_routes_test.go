package main

import (
	"io"
	"net"
	"net/http/httptest"
	"testing"
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
