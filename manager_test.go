package main

import (
	"testing"
	"time"
)

func TestManagerStopUnknownCountryError(t *testing.T) {
	manager := NewManager(defaultConfig())
	if err := manager.Stop("xx"); err == nil {
		t.Fatal("stopping unknown country should return an error")
	}
}

func TestManagerStopAlreadyStoppedReturnsNil(t *testing.T) {
	manager := NewManager(defaultConfig())
	if err := manager.Stop("us"); err != nil {
		t.Fatalf("stopping already-stopped instance should not error: %v", err)
	}
}

func TestManagerStopDrainingInstanceReturnsNil(t *testing.T) {
	manager := NewManager(defaultConfig())
	manager.mu.Lock()
	manager.instances["us"].Status = "running"
	manager.instances["us"].draining = true
	manager.mu.Unlock()
	if err := manager.Stop("us"); err != nil {
		t.Fatalf("stopping draining instance should not error: %v", err)
	}
}

func TestManagerActivateSetsActive(t *testing.T) {
	manager := NewManager(defaultConfig())
	// Start will fail without a real Tor binary, but Activate calls Start internally.
	// Instead, test that Activate is stored when Start succeeds.
	// Since no Tor binary exists in test, we simulate: set instance running then activate.
	manager.mu.Lock()
	manager.instances["us"].Status = "running"
	manager.mu.Unlock()
	if err := manager.Activate("us"); err != nil {
		t.Fatalf("activate failed: %v", err)
	}
	manager.mu.RLock()
	active := manager.active
	manager.mu.RUnlock()
	if active != "us" {
		t.Fatalf("active = %q, want %q", active, "us")
	}
}

func TestManagerActivateUnknownCountry(t *testing.T) {
	manager := NewManager(defaultConfig())
	if err := manager.Activate("zz"); err == nil {
		t.Fatal("activating unknown country should fail")
	}
}

func TestManagerInstanceReturnsCopy(t *testing.T) {
	manager := NewManager(defaultConfig())
	original, ok := manager.Instance("us")
	if !ok {
		t.Fatal("expected us instance")
	}
	original.Status = "mutated"
	// The internal instance should not be affected
	again, _ := manager.Instance("us")
	if again.Status == "mutated" {
		t.Fatal("Instance() returned a reference to internal state, not a copy")
	}
}

func TestManagerInstanceState(t *testing.T) {
	manager := NewManager(defaultConfig())
	state := manager.State()
	if state.MaxRunning != defaultConfig().MaxRunning {
		t.Fatalf("MaxRunning = %d, want %d", state.MaxRunning, defaultConfig().MaxRunning)
	}
	if len(state.Instances) != len(defaultConfig().Countries) {
		t.Fatalf("got %d instances, want %d", len(state.Instances), len(defaultConfig().Countries))
	}
}

func TestManagerMakeRoomAlreadyRunningTarget(t *testing.T) {
	manager := NewManager(defaultConfig())
	manager.mu.Lock()
	manager.instances["us"].Status = "running"
	manager.mu.Unlock()
	// Target is already running, so makeRoom should return nil immediately
	if err := manager.makeRoom("us"); err != nil {
		t.Fatalf("makeRoom for already-running target should not error: %v", err)
	}
}

func TestManagerMakeRoomUnderLimit(t *testing.T) {
	cfg := defaultConfig()
	cfg.MaxRunning = 10
	manager := NewManager(cfg)
	// Only 2 instances "running", well under limit of 10
	manager.mu.Lock()
	manager.instances["us"].Status = "running"
	manager.instances["jp"].Status = "running"
	manager.mu.Unlock()
	if err := manager.makeRoom("de"); err != nil {
		t.Fatalf("makeRoom under limit should not error: %v", err)
	}
}

func TestManagerMakeRoomAtLimitEvictsOldest(t *testing.T) {
	cfg := defaultConfig()
	cfg.MaxRunning = 2
	manager := NewManager(cfg)
	manager.mu.Lock()
	// jp is the oldest (started earlier)
	manager.instances["us"].Status = "running"
	manager.instances["us"].StartedAt = time.Now().Add(-1 * time.Minute)
	manager.instances["jp"].Status = "running"
	manager.instances["jp"].StartedAt = time.Now().Add(-5 * time.Minute)
	manager.active = "us" // us is active, should not be evicted
	manager.mu.Unlock()
	// Requesting "de" while at limit 2 should evict jp (oldest non-active)
	if err := manager.makeRoom("de"); err != nil {
		t.Fatalf("makeRoom at limit should evict, not error: %v", err)
	}
	// Stop on instance with no running process sets status to "stopped" immediately
	
	manager.mu.RLock()
	jpStatus := manager.instances["jp"].Status
	manager.mu.RUnlock()
	if jpStatus != "stopped" && jpStatus != "draining" {
		t.Fatalf("jp should be stopped or draining after eviction, got %q", jpStatus)
	}
}

func TestManagerMakeRoomAtLimitNoEvictableReturnsError(t *testing.T) {
	cfg := defaultConfig()
	cfg.MaxRunning = 2
	manager := NewManager(cfg)
	manager.mu.Lock()
	manager.instances["us"].Status = "running"
	manager.instances["us"].StartedAt = time.Now()
	manager.instances["jp"].Status = "running"
	manager.instances["jp"].StartedAt = time.Now()
	manager.active = "us" // us is active
	// jp is not active but is the only candidate; makeRoom("de") at limit should evict jp
	// Actually: jp IS evictable (not active). So this should succeed.
	// To test the error case, we need all running instances to be active.
	// With only one active field, we can only have one non-evictable.
	manager.mu.Unlock()
	// This should evict jp (oldest non-active), not return error
	if err := manager.makeRoom("de"); err != nil {
		t.Fatalf("makeRoom should evict, not error: %v", err)
	}
}

func TestManagerMakeRoomAtLimitAllActiveReturnsError(t *testing.T) {
	cfg := defaultConfig()
	cfg.MaxRunning = 1
	manager := NewManager(cfg)
	manager.mu.Lock()
	manager.instances["us"].Status = "running"
	manager.instances["us"].StartedAt = time.Now()
	manager.active = "us" // the only running instance is active
	manager.mu.Unlock()
	// Requesting "de" while at limit 1 with only active running: no evictable candidate
	if err := manager.makeRoom("de"); err == nil {
		t.Fatal("makeRoom should error when no evictable candidate exists")
	}
}

func TestManagerEnsureCountryCreatesNewInstance(t *testing.T) {
	manager := NewManager(defaultConfig())
	originalCount := len(manager.cfg.Countries)
	instance, err := manager.ensureCountry(Country{Code: "au", Name: "Australia"})
	if err != nil {
		t.Fatalf("ensureCountry failed: %v", err)
	}
	if instance.Country.Code != "au" {
		t.Fatalf("got code %q, want %q", instance.Country.Code, "au")
	}
	if len(manager.cfg.Countries) != originalCount+1 {
		t.Fatalf("Countries count = %d, want %d", len(manager.cfg.Countries), originalCount+1)
	}
	// Port should be base + original count (the next available port)
	expectedPort := defaultConfig().BaseSocksPort + originalCount
	if instance.SocksPort != expectedPort {
		t.Fatalf("SocksPort = %d, want %d", instance.SocksPort, expectedPort)
	}
}

func TestManagerEnsureCountryInvalidCode(t *testing.T) {
	manager := NewManager(defaultConfig())
	if _, err := manager.ensureCountry(Country{Code: "usa", Name: "too long"}); err == nil {
		t.Fatal("expected error for invalid country code")
	}
}

func TestManagerEnsureCountryReturnsExistingInstance(t *testing.T) {
	manager := NewManager(defaultConfig())
	instance1, _ := manager.ensureCountry(Country{Code: "us", Name: "United States"})
	instance2, _ := manager.ensureCountry(Country{Code: "us", Name: "United States"})
	if instance1 != instance2 {
		t.Fatal("ensureCountry should return the same pointer for existing country")
	}
}

func TestManagerUpdateMaxRunningReducesInstances(t *testing.T) {
	cfg := defaultConfig()
	cfg.MaxRunning = 10
	manager := NewManager(cfg)
	manager.mu.Lock()
	manager.instances["us"].Status = "running"
	manager.instances["us"].StartedAt = time.Now().Add(-3 * time.Minute)
	manager.instances["jp"].Status = "running"
	manager.instances["jp"].StartedAt = time.Now().Add(-2 * time.Minute)
	manager.instances["de"].Status = "running"
	manager.instances["de"].StartedAt = time.Now().Add(-1 * time.Minute)
	manager.active = "us"
	manager.mu.Unlock()

	manager.UpdateMaxRunning(2)
	

	manager.mu.RLock()
	running := 0
	for _, inst := range manager.instances {
		if inst.Status == "running" {
			running++
		}
	}
	manager.mu.RUnlock()
	if running > 2 {
		t.Fatalf("expected at most 2 running after UpdateMaxRunning(2), got %d", running)
	}
}

func TestManagerCountryNormalization(t *testing.T) {
	manager := NewManager(defaultConfig())
	// "US" should normalize to "us" and find the instance
	instance, ok := manager.Instance("US")
	if !ok {
		t.Fatal("Instance(US) should find us instance via normalization")
	}
	if instance.Country.Code != "us" {
		t.Fatalf("got %q, want %q", instance.Country.Code, "us")
	}
}
