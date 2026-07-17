package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type catalogRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn catalogRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestCatalogKeepsCachedNodesWhenRefreshFails(t *testing.T) {
	catalog := NewExitCatalog(defaultConfig())
	catalog.nodes["cached"] = ExitNode{Fingerprint: "cached", CountryCode: "us", IP: "203.0.113.1"}
	catalog.fetchedAt = time.Now().Add(-11 * time.Minute)
	catalog.client = &http.Client{Transport: catalogRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("directory unavailable")
	})}

	if err := catalog.EnsureFresh(context.Background()); err != nil {
		t.Fatalf("EnsureFresh() discarded usable cached nodes: %v", err)
	}
	status := catalog.Status()
	if status.NodeCount != 1 || !status.Stale || !strings.Contains(status.LastError, "directory unavailable") {
		t.Fatalf("unexpected cached catalog status: %#v", status)
	}
}

func TestCatalogInitialFailureIsReturned(t *testing.T) {
	catalog := NewExitCatalog(defaultConfig())
	catalog.client = &http.Client{Transport: catalogRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("directory unavailable")
	})}
	if err := catalog.EnsureFresh(context.Background()); err == nil {
		t.Fatal("initial catalog failure should be returned when no cached nodes exist")
	}
}

func TestCatalogRefreshBypassesFreshCache(t *testing.T) {
	catalog := NewExitCatalog(defaultConfig())
	catalog.nodes["cached"] = ExitNode{Fingerprint: "cached", CountryCode: "us", IP: "203.0.113.1"}
	catalog.fetchedAt = time.Now()
	requests := 0
	catalog.client = &http.Client{Transport: catalogRoundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		body := `{"relays":[{"fingerprint":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","nickname":"test","or_addresses":["198.51.100.8:9001"],"exit_addresses":["198.51.100.8"],"country":"us","country_name":"United States","as":"AS64500","as_name":"Example ISP","consensus_weight":10,"exit_policy_summary":{"accept":["443"]}}]}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}

	if err := catalog.EnsureFresh(context.Background()); err != nil || requests != 0 {
		t.Fatalf("fresh catalog unexpectedly fetched: err=%v requests=%d", err, requests)
	}
	if err := catalog.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requests != 1 || catalog.Status().NodeCount != 1 {
		t.Fatalf("forced refresh requests=%d status=%#v", requests, catalog.Status())
	}
}
