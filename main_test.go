package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeJSONRejectsTrailingValue(t *testing.T) {
	request := httptest.NewRequest("POST", "/", strings.NewReader(`{"value":1}{"value":2}`))
	var input struct {
		Value int `json:"value"`
	}
	if err := decodeJSON(request, &input); err == nil {
		t.Fatal("decodeJSON() accepted a second JSON value")
	}
}

func TestDecodeJSONAcceptsSingleValue(t *testing.T) {
	request := httptest.NewRequest("POST", "/", strings.NewReader(`{"value":1}`))
	var input struct {
		Value int `json:"value"`
	}
	if err := decodeJSON(request, &input); err != nil {
		t.Fatal(err)
	}
	if input.Value != 1 {
		t.Fatalf("decoded value = %d, want 1", input.Value)
	}
}
