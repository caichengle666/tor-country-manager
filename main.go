package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

//go:embed web/*
var webFiles embed.FS

func main() {
	configPath := flag.String("config", defaultConfigPath(), "configuration file")
	writeConfig := flag.Bool("write-example-config", false, "write an example configuration and exit")
	flag.Parse()
	if *writeConfig {
		if err := writeExampleConfig(*configPath); err != nil {
			log.Fatal(err)
		}
		fmt.Println("wrote", *configPath)
		return
	}
	loaded, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	cfg := loaded.Effective
	if err := os.MkdirAll(cfg.StateDir, 0o750); err != nil {
		log.Fatal(err)
	}

	manager := NewManager(cfg)
	catalog := NewExitCatalog(cfg)
	configStore := NewConfigStore(*configPath, loaded.Stored)
	authStore, err := NewAuthStore(cfg)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		if err := manager.ServeProxy(ctx); err != nil {
			log.Printf("proxy: %v", err)
			stop()
		}
	}()
	manager.StartCountryProxies(ctx)
	manager.Restore()

	server := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           routes(manager, catalog, configStore, authStore, cfg),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		log.Printf("web manager listening on http://%s", cfg.ListenAddress)
		log.Printf("unified SOCKS5 proxy listening on %s", cfg.ProxyAddress)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("web server: %v", err)
			stop()
		}
	}()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
	manager.Shutdown()
}

func defaultConfigPath() string {
	if runtime.GOOS != "windows" {
		return "/var/lib/tor-country-manager/config.json"
	}
	executable, err := os.Executable()
	if err != nil {
		return "config.json"
	}
	return filepath.Join(filepath.Dir(executable), "config.json")
}

func routes(manager *Manager, catalog *ExitCatalog, configStore *ConfigStore, authStore *AuthStore, cfg Config) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/session", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"configured": authStore.Configured(), "authenticated": authStore.ValidSession(r)})
	})
	mux.HandleFunc("POST /api/setup-password", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Password string `json:"password"`
		}
		if err := decodeJSON(r, &input); err != nil {
			writeError(w, err)
			return
		}
		if err := authStore.Setup(input.Password); err != nil {
			writeError(w, err)
			return
		}
		if err := authStore.CreateSession(w); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]bool{"authenticated": true})
	})
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Password string `json:"password"`
		}
		if err := decodeJSON(r, &input); err != nil {
			writeError(w, err)
			return
		}
		authenticated, retryAfter := authStore.Authenticate(loginClientKey(r), input.Password)
		if retryAfter > 0 {
			seconds := int((retryAfter + time.Second - 1) / time.Second)
			w.Header().Set("Retry-After", fmt.Sprintf("%d", seconds))
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many login attempts; try again later"})
			return
		}
		if !authenticated {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "administrator password is incorrect"})
			return
		}
		if err := authStore.CreateSession(w); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
	})
	mux.HandleFunc("POST /api/logout", func(w http.ResponseWriter, r *http.Request) {
		authStore.DeleteSession(w, r)
		writeJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
	})
	mux.HandleFunc("GET /api/settings/upstream", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, configStore.Upstream())
	})
	mux.HandleFunc("GET /api/settings/runtime", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, configStore.Runtime())
	})
	mux.HandleFunc("GET /api/settings/client", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, configStore.Client(cfg.ClientAPIKey != ""))
	})
	mux.HandleFunc("PUT /api/settings/client", func(w http.ResponseWriter, r *http.Request) {
		var update ClientUpdate
		if err := decodeJSON(r, &update); err != nil {
			writeError(w, err)
			return
		}
		restartRequired := update.Host != cfg.CountryProxyHost || update.BasePort != cfg.CountryProxyPort
		generated, err := configStore.UpdateClient(update)
		if err != nil {
			writeError(w, err)
			return
		}
		effectiveKey := configStore.ClientAPIKey()
		externalKey := os.Getenv("TOR_CLIENT_API_KEY")
		if externalKey != "" {
			effectiveKey = externalKey
		}
		manager.UpdateClientAPIKey(effectiveKey)
		response := map[string]any{"settings": configStore.Client(effectiveKey != ""), "restart_required": restartRequired, "api_key_applied": true}
		if externalKey != "" {
			response["managed_by_environment"] = true
		}
		if generated != "" {
			response["api_key"] = generated
		}
		writeJSON(w, http.StatusOK, response)
	})
	mux.HandleFunc("PUT /api/settings/runtime", func(w http.ResponseWriter, r *http.Request) {
		var input RuntimeSettings
		if err := decodeJSON(r, &input); err != nil {
			writeError(w, err)
			return
		}
		if err := configStore.UpdateRuntime(input); err != nil {
			writeError(w, err)
			return
		}
		manager.UpdateMaxRunning(input.MaxRunning)
		manager.UpdateCircuitRotateMinutes(input.CircuitRotateMinutes)
		writeJSON(w, http.StatusOK, map[string]any{"settings": configStore.Runtime(), "applied": true})
	})
	mux.HandleFunc("PUT /api/settings/upstream", func(w http.ResponseWriter, r *http.Request) {
		var update UpstreamUpdate
		if err := decodeJSON(r, &update); err != nil {
			writeError(w, err)
			return
		}
		if err := configStore.UpdateUpstream(update); err != nil {
			writeError(w, err)
			return
		}
		cfg := configStore.Config()
		managedByEnvironment := false
		if proxy := os.Getenv("TOR_UPSTREAM_SOCKS5"); proxy != "" {
			cfg.UpstreamSOCKS5 = proxy
			cfg.UpstreamUsername = os.Getenv("TOR_UPSTREAM_USERNAME")
			cfg.UpstreamPassword = os.Getenv("TOR_UPSTREAM_PASSWORD")
			managedByEnvironment = true
		}
		if err := manager.UpdateUpstream(cfg); err != nil {
			writeError(w, err)
			return
		}
		catalog.UpdateUpstream(cfg)
		writeJSON(w, http.StatusOK, map[string]any{"settings": configStore.Upstream(), "applied": true, "managed_by_environment": managedByEnvironment})
	})
	mux.HandleFunc("PUT /api/settings/password", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			CurrentPassword string `json:"current_password"`
			NewPassword     string `json:"new_password"`
		}
		if err := decodeJSON(r, &input); err != nil {
			writeError(w, err)
			return
		}
		if err := authStore.Change(input.CurrentPassword, input.NewPassword); err != nil {
			writeError(w, err)
			return
		}
		if err := configStore.ClearLegacyAuth(); err != nil {
			writeError(w, err)
			return
		}
		if err := authStore.CreateSession(w); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"changed": true})
	})
	mux.HandleFunc("GET /api/state", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, manager.State()) })
	mux.HandleFunc("POST /api/countries/{code}/start", func(w http.ResponseWriter, r *http.Request) {
		if err := manager.Start(r.PathValue("code")); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, manager.State())
	})
	mux.HandleFunc("POST /api/countries/{code}/stop", func(w http.ResponseWriter, r *http.Request) {
		if err := manager.Stop(r.PathValue("code")); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, manager.State())
	})
	mux.HandleFunc("POST /api/countries/{code}/cancel-switch", func(w http.ResponseWriter, r *http.Request) {
		if err := manager.CancelReplacement(r.PathValue("code")); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, manager.State())
	})
	mux.HandleFunc("POST /api/countries/{code}/activate", func(w http.ResponseWriter, r *http.Request) {
		if err := manager.Activate(r.PathValue("code")); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, manager.State())
	})
	mux.HandleFunc("GET /api/countries/{code}/log", func(w http.ResponseWriter, r *http.Request) {
		code := normalizeCode(r.PathValue("code"))
		if !countryCodePattern.MatchString(code) {
			writeError(w, errors.New("invalid country code"))
			return
		}
		text, err := tailFile(filepath.Join(cfg.StateDir, code, "logs", "tor.log"), 200)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"log": text})
	})
	mux.HandleFunc("GET /api/exits/countries", func(w http.ResponseWriter, r *http.Request) {
		if err := catalog.EnsureFresh(r.Context()); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"countries": catalog.Countries(), "status": catalog.Status()})
	})
	mux.HandleFunc("POST /api/exits/refresh", func(w http.ResponseWriter, r *http.Request) {
		err := catalog.Refresh(r.Context())
		status := catalog.Status()
		if err != nil && status.NodeCount == 0 {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"countries": catalog.Countries(), "status": status})
	})
	mux.HandleFunc("GET /api/exits/countries/{code}", func(w http.ResponseWriter, r *http.Request) {
		code := normalizeCode(r.PathValue("code"))
		if !countryCodePattern.MatchString(code) {
			writeError(w, errors.New("invalid country code"))
			return
		}
		if err := catalog.EnsureFresh(r.Context()); err != nil {
			writeError(w, err)
			return
		}
		catalog.StartLatencyChecks(code)
		writeJSON(w, http.StatusOK, map[string]any{"nodes": catalog.NodesForCountry(code)})
	})
	mux.HandleFunc("POST /api/exits/nodes/{fingerprint}/activate", func(w http.ResponseWriter, r *http.Request) {
		if err := catalog.EnsureFresh(r.Context()); err != nil {
			writeError(w, err)
			return
		}
		node, ok := catalog.Node(r.PathValue("fingerprint"))
		if !ok {
			writeError(w, errors.New("Tor exit node is no longer available"))
			return
		}
		if err := manager.ActivateNode(node); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, manager.State())
	})
	mux.HandleFunc("GET /api/v1/countries", func(w http.ResponseWriter, r *http.Request) {
		if err := catalog.EnsureFresh(r.Context()); err != nil {
			writeError(w, err)
			return
		}
		countries := catalog.Countries()
		result := make([]map[string]any, 0, len(countries))
		for _, country := range countries {
			port, _ := countryPort(cfg.CountryProxyPort, country.Code)
			result = append(result, map[string]any{"code": country.Code, "name": country.Name, "continent": country.Continent, "node_count": country.NodeCount, "socks5_port": port})
		}
		writeJSON(w, http.StatusOK, map[string]any{"countries": result, "policies": []string{"lowest_latency", "failover"}})
	})
	mux.HandleFunc("POST /api/v1/routes", func(w http.ResponseWriter, r *http.Request) {
		var input RouteRequest
		if err := decodeJSON(r, &input); err != nil {
			writeError(w, err)
			return
		}
		candidates := input.Countries
		if input.Country != "" {
			candidates = append([]string{input.Country}, candidates...)
		}
		if err := catalog.EnsureFresh(r.Context()); err != nil {
			writeError(w, err)
			return
		}
		node, err := catalog.SelectNode(r.Context(), candidates, input.Policy)
		if err != nil {
			writeError(w, err)
			return
		}
		if err := manager.StartNode(node); err != nil {
			writeError(w, err)
			return
		}
		if _, err := manager.EnsureCountryProxy(node.CountryCode); err != nil {
			writeError(w, err)
			return
		}
		route, _ := clientRouteForRequest(manager, cfg, r, node.CountryCode)
		route.LatencyMS = node.LatencyMS
		writeJSON(w, http.StatusAccepted, route)
	})
	mux.HandleFunc("GET /api/v1/routes/{code}", func(w http.ResponseWriter, r *http.Request) {
		route, err := clientRouteForRequest(manager, cfg, r, r.PathValue("code"))
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, route)
	})
	mux.HandleFunc("DELETE /api/v1/routes/{code}", func(w http.ResponseWriter, r *http.Request) {
		if err := manager.Stop(r.PathValue("code")); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]bool{"stopping": true})
	})
	assets, _ := fs.Sub(webFiles, "web")
	mux.Handle("/", http.FileServer(http.FS(assets)))
	return securityHeaders(authAPI(mux, authStore, manager.clientAuth))
}

func authAPI(next http.Handler, authStore *AuthStore, clientAuth *RuntimeClientAuth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/") {
			if !validBearerToken(r, clientAuth) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "valid client API Bearer token required"})
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && !publicAPIPath(r.URL.Path) {
			if !authStore.Configured() {
				writeJSON(w, http.StatusPreconditionRequired, map[string]string{"error": "administrator password has not been configured"})
				return
			}
			if !authStore.ValidSession(r) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
				return
			}
			if r.Method != http.MethodGet && !sameOriginRequest(r) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request rejected"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func publicAPIPath(path string) bool {
	return path == "/api/session" || path == "/api/login" || path == "/api/setup-password"
}

func sameOriginRequest(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	return err == nil && parsed.Host == r.Host && (parsed.Scheme == "http" || parsed.Scheme == "https")
}

func loginClientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func decodeJSON(r *http.Request, target any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid JSON request: %w", err)
	}
	return nil
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
}
