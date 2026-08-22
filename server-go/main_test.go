package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSameOriginAcceptsPublishedHostForwardedByProxy(t *testing.T) {
	req := httptest.NewRequest("GET", "http://internal-service/api/ws", nil)
	req.Host = "internal-service"
	req.Header.Set("Origin", "https://veilchat-3zdzwwqm.manus.space")
	req.Header.Set("X-Forwarded-Host", "veilchat-3zdzwwqm.manus.space")
	if !sameOrigin(req) {
		t.Fatal("expected public origin preserved by reverse proxy to be accepted")
	}
	if got := publicRequestHost(req); got != "veilchat-3zdzwwqm.manus.space" {
		t.Fatalf("publicRequestHost() = %q", got)
	}
}

func TestSameOriginRejectsMismatchedOrMalformedOrigins(t *testing.T) {
	for _, origin := range []string{
		"https://evil.example",
		"https://veilchat-3zdzwwqm.manus.space.evil.example",
		"https://veilchat-3zdzwwqm.manus.space/unexpected",
	} {
		req := httptest.NewRequest("GET", "http://internal-service/api/ws", nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("X-Forwarded-Host", "veilchat-3zdzwwqm.manus.space")
		if sameOrigin(req) {
			t.Fatalf("expected origin %q to be rejected", origin)
		}
	}
}

func TestSameOriginAllowsHTTPOnlyForLocalDevelopment(t *testing.T) {
	req := httptest.NewRequest("GET", "http://localhost:3000/api/ws", nil)
	req.Host = "localhost:3000"
	req.Header.Set("Origin", "http://localhost:3000")
	if !sameOrigin(req) {
		t.Fatal("expected local development origin to be accepted")
	}
}

func TestSecurityHeadersAllowOnlyRequiredHostedResources(t *testing.T) {
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://veilchat-3zdzwwqm.manus.space/", nil))

	policy := response.Header().Get("Content-Security-Policy")
	for _, expected := range []string{
		"script-src 'self' 'unsafe-inline' https://files.manuscdn.com https://plausible.io",
		"img-src 'self' data: https://files.manuscdn.com",
		"frame-ancestors 'none'",
	} {
		if !strings.Contains(policy, expected) {
			t.Fatalf("CSP missing %q: %s", expected, policy)
		}
	}
	if strings.Contains(policy, "unsafe-eval") || strings.Contains(policy, "*") {
		t.Fatalf("CSP is broader than intended: %s", policy)
	}
}

func TestServeAppReturnsValidIconForFaviconRequest(t *testing.T) {
	assets := t.TempDir()
	if err := os.WriteFile(filepath.Join(assets, "favicon.svg"), []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`), 0o600); err != nil {
		t.Fatal(err)
	}
	server := &apiServer{assets: assets}
	response := httptest.NewRecorder()
	server.serveApp(response, httptest.NewRequest(http.MethodGet, "https://example.test/favicon.ico", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("favicon status = %d", response.Code)
	}
	if !strings.Contains(response.Header().Get("Content-Type"), "image/svg+xml") {
		t.Fatalf("favicon content type = %q", response.Header().Get("Content-Type"))
	}
}
