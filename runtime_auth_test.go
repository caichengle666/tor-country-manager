package main

import "testing"

func TestRuntimeClientAuthKey(t *testing.T) {
	auth := NewRuntimeClientAuth("initial-key")
	if auth.Key() != "initial-key" {
		t.Fatalf("Key() = %q, want %q", auth.Key(), "initial-key")
	}
}

func TestRuntimeClientAuthUpdate(t *testing.T) {
	auth := NewRuntimeClientAuth("original")
	auth.Update("replacement")
	if auth.Key() != "replacement" {
		t.Fatalf("Key() = %q after Update, want %q", auth.Key(), "replacement")
	}
}

func TestRuntimeClientAuthValid(t *testing.T) {
	auth := NewRuntimeClientAuth("my-secret")
	if !auth.Valid("my-secret") {
		t.Fatal("correct key was rejected")
	}
	if auth.Valid("other-secret") {
		t.Fatal("wrong key was accepted")
	}
}

func TestRuntimeClientAuthValidRejectsEmpty(t *testing.T) {
	auth := NewRuntimeClientAuth("")
	if auth.Valid("") {
		t.Fatal("empty key was accepted when no key is configured")
	}
	if auth.Valid("anything") {
		t.Fatal("non-empty key was accepted when no key is configured")
	}
}

func TestRuntimeClientAuthHotUpdate(t *testing.T) {
	auth := NewRuntimeClientAuth("first-key")
	if !auth.Valid("first-key") {
		t.Fatal("first key was rejected")
	}
	auth.Update("second-key")
	if auth.Valid("first-key") {
		t.Fatal("old key was still valid after hot update")
	}
	if !auth.Valid("second-key") {
		t.Fatal("new key was not valid after hot update")
	}
}

func TestRuntimeClientAuthEmptyUpdate(t *testing.T) {
	auth := NewRuntimeClientAuth("configured-key")
	auth.Update("")
	if auth.Valid("configured-key") {
		t.Fatal("old key should not be valid after updating to empty")
	}
	if auth.Valid("") {
		t.Fatal("empty key should not be valid")
	}
}
