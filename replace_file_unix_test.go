//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRewriteMountedFile(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "temporary")
	destination := filepath.Join(directory, "config.json")
	if err := os.WriteFile(source, []byte("new configuration\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("old configuration\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := rewriteMountedFile(source, destination); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "new configuration\n" {
		t.Fatalf("saved %q", contents)
	}
}
