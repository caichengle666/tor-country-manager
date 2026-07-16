package main

import "testing"

func TestAcquireInstanceTracksConnections(t *testing.T) {
	manager := NewManager(defaultConfig())
	manager.mu.Lock()
	instance := manager.instances["us"]
	instance.Status = "running"
	manager.mu.Unlock()

	acquired, ok := manager.acquireInstance("us")
	if !ok || acquired != instance || instance.ActiveConnections != 1 {
		t.Fatal("running instance was not acquired")
	}
	manager.releaseInstance(acquired)
	if instance.ActiveConnections != 0 {
		t.Fatal("connection count was not released")
	}
	manager.mu.Lock()
	instance.draining = true
	manager.mu.Unlock()
	if _, ok := manager.acquireInstance("us"); ok {
		t.Fatal("draining instance accepted a new connection")
	}
}

func TestReplacementKeepsOldConnectionsSeparate(t *testing.T) {
	manager := NewManager(defaultConfig())
	old := manager.instances["us"]
	old.Status = "draining"
	old.ActiveConnections = 3
	old.draining = true
	replacement := &Instance{Country: old.Country, SocksPort: 25000, Status: "running", DrainingConnections: old.ActiveConnections}
	manager.instances["us"] = replacement

	acquired, ok := manager.acquireInstance("us")
	if !ok || acquired != replacement {
		t.Fatal("new connections did not switch to replacement instance")
	}
	manager.releaseInstance(acquired)
	if old.ActiveConnections != 3 {
		t.Fatal("old connections were changed while using replacement")
	}
}
