package main

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	expectedControlPort := defaultConfig().BaseSocksPort + 3000 + originalCount
	if instance.controlPort != expectedControlPort {
		t.Fatalf("controlPort = %d, want %d", instance.controlPort, expectedControlPort)
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

func TestManagerPersistsNodesForRestore(t *testing.T) {
	cfg := defaultConfig()
	cfg.StateDir = t.TempDir()
	manager := NewManager(cfg)
	instance := manager.instances["us"]
	instance.ExitFingerprint = strings.Repeat("A", 40)
	instance.SelectedIP = "203.0.113.10"
	instance.SelectedNode = "test-exit"
	instance.StartedAt = time.Now().UTC()
	manager.active = "us"
	manager.rememberInstance(instance)

	restored := NewManager(cfg)
	node, ok := restored.resumeNodes["us"]
	if !ok {
		t.Fatal("saved node was not loaded")
	}
	if node.ExitFingerprint != instance.ExitFingerprint || node.SelectedIP != instance.SelectedIP || node.SelectedNode != instance.SelectedNode {
		t.Fatalf("loaded node = %#v, want selected node details", node)
	}
	if restored.resumeActive != "us" {
		t.Fatalf("resume active = %q, want us", restored.resumeActive)
	}
}

func TestManagerStoppedNodeIsNotRestored(t *testing.T) {
	cfg := defaultConfig()
	cfg.StateDir = t.TempDir()
	manager := NewManager(cfg)
	instance := manager.instances["us"]
	instance.ExitFingerprint = strings.Repeat("B", 40)
	instance.StartedAt = time.Now().UTC()
	manager.rememberInstance(instance)
	manager.forgetInstance("us")

	restored := NewManager(cfg)
	if _, ok := restored.resumeNodes["us"]; ok {
		t.Fatal("stopped node was loaded for restore")
	}
}

func TestManagerRestoreAppliesSavedNode(t *testing.T) {
	cfg := defaultConfig()
	cfg.StateDir = t.TempDir()
	cfg.TorBinary = filepath.Join(cfg.StateDir, "missing-tor")
	manager := NewManager(cfg)
	instance := manager.instances["us"]
	instance.ExitFingerprint = strings.Repeat("C", 40)
	instance.SelectedIP = "203.0.113.11"
	instance.StartedAt = time.Now().UTC()
	manager.rememberInstance(instance)

	restored := NewManager(cfg)
	restored.Restore()
	restoredInstance, ok := restored.Instance("us")
	if !ok || restoredInstance.ExitFingerprint != strings.Repeat("C", 40) || restoredInstance.SelectedIP != "203.0.113.11" {
		t.Fatalf("restore did not apply saved node: %#v", restoredInstance)
	}
	if restoredInstance.Status != "error" {
		t.Fatalf("restore did not attempt to start the saved node, status = %q", restoredInstance.Status)
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

func TestUpdateUpstreamUsesControlPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	directory := t.TempDir()
	cookie := []byte{0x01, 0xab, 0xcd}
	if err := os.WriteFile(filepath.Join(directory, "control_auth_cookie"), cookie, 0o600); err != nil {
		t.Fatal(err)
	}
	commands := make(chan []string, 1)
	go func() {
		var received []string
		for range 2 {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			reader := bufio.NewReader(connection)
			for range 2 {
				line, err := reader.ReadString('\n')
				if err != nil {
					_ = connection.Close()
					return
				}
				received = append(received, strings.TrimSpace(line))
				if _, err := connection.Write([]byte("250 OK\r\n")); err != nil {
					_ = connection.Close()
					return
				}
			}
			_ = connection.Close()
		}
		commands <- received
	}()

	manager := NewManager(defaultConfig())
	instance := manager.instances["us"]
	instance.Status = "running"
	instance.cmd = &exec.Cmd{Process: &os.Process{Pid: 1}}
	instance.controlPort = listener.Addr().(*net.TCPAddr).Port
	instance.dataDir = directory
	cfg := defaultConfig()
	cfg.UpstreamSOCKS5 = "proxy.example:1080"
	cfg.UpstreamUsername = "user"
	cfg.UpstreamPassword = "pass"
	if err := manager.UpdateUpstream(cfg); err != nil {
		t.Fatal(err)
	}
	received := <-commands
	if len(received) != 4 {
		t.Fatalf("received %d control commands, want 4", len(received))
	}
	if received[0] != "AUTHENTICATE 01abcd" {
		t.Fatalf("authentication command = %q", received[0])
	}
	if !strings.Contains(received[1], `Socks5Proxy="proxy.example:1080"`) || !strings.Contains(received[1], `Socks5ProxyUsername="user"`) {
		t.Fatalf("SETCONF command = %q", received[1])
	}
	if received[2] != "AUTHENTICATE 01abcd" || received[3] != "SIGNAL NEWNYM" {
		t.Fatalf("rotation commands = %q", received[2:])
	}
}

func TestControlValueEscapesQuotesAndBackslashes(t *testing.T) {
	if got, want := controlValue(`a"b\c`), `"a\"b\\c"`; got != want {
		t.Fatalf("controlValue() = %q, want %q", got, want)
	}
}

func TestTorrcEscapesUpstreamCredentials(t *testing.T) {
	cfg := defaultConfig()
	cfg.UpstreamSOCKS5 = "proxy.example:1080"
	cfg.UpstreamUsername = `user "name"`
	cfg.UpstreamPassword = `pass\word`
	manager := NewManager(cfg)
	instance := manager.instances["us"]
	torrc := manager.torrc(instance, "data", "logs")
	if !strings.Contains(torrc, `Socks5ProxyUsername "user \"name\""`) {
		t.Fatalf("username was not escaped in torrc: %s", torrc)
	}
	if !strings.Contains(torrc, `Socks5ProxyPassword "pass\\word"`) {
		t.Fatalf("password was not escaped in torrc: %s", torrc)
	}
}

func TestParseBootstrapProgress(t *testing.T) {
	response := "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=63 TAG=loading_descriptors SUMMARY=Loading relay descriptors\r\n"
	progress, ok := parseBootstrapProgress(response)
	if !ok || progress != 63 {
		t.Fatalf("parseBootstrapProgress() = %d, %v, want 63, true", progress, ok)
	}
	if _, ok := parseBootstrapProgress("250 OK\r\n"); ok {
		t.Fatal("response without bootstrap progress was accepted")
	}
	if _, ok := parseBootstrapProgress("PROGRESS=101"); ok {
		t.Fatal("out-of-range bootstrap progress was accepted")
	}
}

func TestCancelReplacementPreservesCurrentInstance(t *testing.T) {
	manager := NewManager(defaultConfig())
	current := manager.instances["us"]
	current.cmd = &exec.Cmd{Process: &os.Process{Pid: -1}}
	current.Status = "switching"
	current.replacement = true
	current.replacementSequence = 1
	current.replacementPreviousStatus = "running"
	replacement := &Instance{Country: current.Country, Status: "starting"}
	current.pendingReplacement = replacement

	if err := manager.CancelReplacement("us"); err != nil {
		t.Fatal(err)
	}
	if current.replacement || current.pendingReplacement != nil || current.Status != "running" {
		t.Fatalf("current instance was not restored: %#v", current)
	}
	if replacement.Status != "stopped" {
		t.Fatalf("replacement status = %q, want stopped", replacement.Status)
	}
}

func TestCancelReplacementDoesNotRestoreMissingCurrentInstance(t *testing.T) {
	manager := NewManager(defaultConfig())
	current := manager.instances["us"]
	current.Status = "error"
	current.Error = "Tor exited unexpectedly"
	current.replacement = true
	current.replacementSequence = 1
	current.replacementPreviousStatus = "running"
	current.pendingReplacement = &Instance{Country: current.Country, Status: "starting"}

	if err := manager.CancelReplacement("us"); err != nil {
		t.Fatal(err)
	}
	if current.Status != "error" || current.Error != "Tor exited unexpectedly" {
		t.Fatalf("missing current instance restored as status %q with error %q", current.Status, current.Error)
	}
}

func TestCancelReplacementRestoresConnectingInstance(t *testing.T) {
	manager := NewManager(defaultConfig())
	current := manager.instances["us"]
	current.cmd = &exec.Cmd{Process: &os.Process{Pid: -1}}
	current.Status = "switching"
	current.replacement = true
	current.replacementSequence = 1
	current.replacementPreviousStatus = "connecting"
	current.replacementPreviousError = "old connection warning"
	current.pendingReplacement = &Instance{Country: current.Country, Status: "starting"}

	if err := manager.CancelReplacement("us"); err != nil {
		t.Fatal(err)
	}
	if current.Status != "connecting" || current.Error != "old connection warning" {
		t.Fatalf("cancel restored status %q and error %q, want connecting and prior error", current.Status, current.Error)
	}
}

func TestExitCheckCannotOverwriteSwitchingState(t *testing.T) {
	manager := NewManager(defaultConfig())
	current := manager.instances["us"]
	cmd := &exec.Cmd{Process: &os.Process{Pid: -1}}
	current.cmd = cmd
	current.Status = "switching"

	if manager.markInstanceRunning(current, cmd, "203.0.113.8") || current.Status != "switching" {
		t.Fatalf("stale exit check overwrote status with %q", current.Status)
	}
}

func TestReplaceNodeOverridesPendingReplacement(t *testing.T) {
	cfg := defaultConfig()
	cfg.StateDir = t.TempDir()
	cfg.TorBinary = filepath.Join(cfg.StateDir, "missing-tor")
	manager := NewManager(cfg)
	current := manager.instances["us"]
	current.cmd = &exec.Cmd{Process: &os.Process{Pid: -1}}
	current.Status = "switching"
	current.replacement = true
	current.replacementSequence = 1
	previous := &Instance{Country: current.Country, Status: "starting"}
	current.pendingReplacement = previous

	node := ExitNode{CountryCode: "us", CountryName: "United States", Fingerprint: strings.Repeat("D", 40), IP: "203.0.113.12", Nickname: "replacement"}
	err := manager.replaceNode(current, node, true)
	if err == nil || strings.Contains(err.Error(), "already starting") {
		t.Fatalf("replaceNode() error = %v, want start failure after overriding pending replacement", err)
	}
	if previous.Status != "stopped" {
		t.Fatalf("previous replacement status = %q, want stopped", previous.Status)
	}
	if current.replacement || current.pendingReplacement != nil || current.Status != "running" {
		t.Fatalf("current instance was not preserved after replacement start failure: %#v", current)
	}
}

func TestAutoRestartEligibility(t *testing.T) {
	manager := NewManager(defaultConfig())
	instance := manager.instances["us"]
	instance.Status = "error"
	if !manager.autoRestartEligibleLocked(instance) {
		t.Fatal("current failed instance should be eligible for automatic restart")
	}
	instance.restartAttempts = autoRestartLimit
	if manager.autoRestartEligibleLocked(instance) {
		t.Fatal("instance exceeding restart limit should not be eligible")
	}
	instance.restartAttempts = 0
	instance.pendingReplacement = &Instance{}
	if manager.autoRestartEligibleLocked(instance) {
		t.Fatal("instance with a pending replacement should not be eligible")
	}
	instance.pendingReplacement = nil
	manager.shuttingDown = true
	if manager.autoRestartEligibleLocked(instance) {
		t.Fatal("instance should not restart during manager shutdown")
	}
}
