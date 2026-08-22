package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nhooyr.io/websocket"
)

type apiServer struct {
	manager *SessionManager
	assets  string
}

func main() {
	server := &apiServer{manager: NewSessionManager(), assets: resolveAssetsDir()}
	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "3000"
	}
	httpServer := &http.Server{
		Addr:              ":" + port,
		Handler:           server.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	fmt.Printf("Server running on http://localhost:%s/\n", port)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		panic(err)
	}
}

func (s *apiServer) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/sessions", s.createSession)
	mux.HandleFunc("POST /api/sessions/{sessionID}/join", s.joinSession)
	mux.HandleFunc("POST /api/sessions/{sessionID}/leave", s.leaveSession)
	mux.HandleFunc("GET /api/sessions/{sessionID}/status", s.getStatus)
	mux.HandleFunc("GET /api/ws", s.webSocket)
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/", s.serveApp)
	return securityHeaders(mux)
}

func resolveAssetsDir() string {
	if configured := strings.TrimSpace(os.Getenv("ASSETS_DIR")); configured != "" {
		return configured
	}
	for _, candidate := range []string{"dist/public", "../dist/public"} {
		if _, err := os.Stat(filepath.Join(candidate, "index.html")); err == nil {
			return candidate
		}
	}
	return "dist/public"
}

func (s *apiServer) serveApp(w http.ResponseWriter, r *http.Request) {
	requestedPath := strings.TrimPrefix(filepath.Clean(r.URL.Path), "/")
	if requestedPath != "" && staticExists(s.assets, requestedPath) {
		http.ServeFile(w, r, filepath.Join(s.assets, requestedPath))
		return
	}
	http.ServeFile(w, r, filepath.Join(s.assets, "index.html"))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self' wss: https:; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *apiServer) createSession(w http.ResponseWriter, r *http.Request) {
	id, token, err := s.manager.Create()
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "secure_random_unavailable")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"sessionId": id, "token": token})
}

func (s *apiServer) joinSession(w http.ResponseWriter, r *http.Request) {
	token, err := s.manager.Join(r.PathValue("sessionID"))
	if err != nil {
		writeSessionError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"token": token})
}

func (s *apiServer) leaveSession(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		writeAPIError(w, http.StatusUnauthorized, "invalid_capability")
		return
	}
	if err := s.manager.Leave(r.PathValue("sessionID"), token); err != nil {
		writeSessionError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *apiServer) getStatus(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		writeAPIError(w, http.StatusUnauthorized, "invalid_capability")
		return
	}
	status, err := s.manager.Status(r.PathValue("sessionID"), token)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *apiServer) webSocket(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("sessionId")
	token := r.URL.Query().Get("token")
	if id == "" || token == "" || !sameOrigin(r) {
		writeAPIError(w, http.StatusForbidden, "connection_refused")
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{r.Host}})
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "connection closed")
	if _, err := s.manager.Attach(id, token, conn); err != nil {
		_ = conn.Close(websocket.StatusPolicyViolation, "session unavailable")
		return
	}
	defer s.manager.Disconnect(id, token, conn)

	for {
		typeID, payload, err := conn.Read(r.Context())
		if err != nil {
			return
		}
		if typeID != websocket.MessageText {
			_ = conn.Close(websocket.StatusUnsupportedData, "text envelopes only")
			return
		}
		if err := s.manager.Relay(id, token, payload); err != nil {
			_ = conn.Close(websocket.StatusPolicyViolation, "relay rejected")
			return
		}
	}
}

func bearerToken(r *http.Request) string {
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(value, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(value, "Bearer "))
	}
	return ""
}

func sameOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return false
	}
	return strings.HasPrefix(origin, "https://"+r.Host) || (strings.HasPrefix(origin, "http://") && (strings.HasPrefix(r.Host, "localhost") || strings.HasPrefix(r.Host, "127.0.0.1")))
}

func writeSessionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errSessionNotFound):
		writeAPIError(w, http.StatusNotFound, "session_unavailable")
	case errors.Is(err, errSessionLocked):
		writeAPIError(w, http.StatusLocked, "session_locked")
	case errors.Is(err, errUnauthorized):
		writeAPIError(w, http.StatusUnauthorized, "invalid_capability")
	default:
		writeAPIError(w, http.StatusGone, "session_closing")
	}
}

func writeAPIError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func staticExists(root, requestPath string) bool {
	path := filepath.Join(root, strings.TrimPrefix(filepath.Clean(requestPath), "/"))
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return true
}
