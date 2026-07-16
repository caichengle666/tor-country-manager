//go:build !windows

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

func replaceFile(source, destination string) error {
	err := os.Rename(source, destination)
	if err == nil || !errors.Is(err, syscall.EBUSY) {
		return err
	}

	// A bind-mounted Docker file cannot be replaced, so update that mount in place.
	return rewriteMountedFile(source, destination)
}

func rewriteMountedFile(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open temporary configuration: %w", err)
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return fmt.Errorf("open mounted configuration: %w", err)
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		return fmt.Errorf("write mounted configuration: %w", err)
	}
	if err := output.Sync(); err != nil {
		output.Close()
		return fmt.Errorf("sync mounted configuration: %w", err)
	}
	if err := output.Close(); err != nil {
		return fmt.Errorf("close mounted configuration: %w", err)
	}
	return nil
}
