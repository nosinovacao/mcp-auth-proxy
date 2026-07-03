package auth

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func newTestDistributedResolver(t *testing.T, allowlist []string) *distributedClaimsResolver {
	t.Helper()
	r, err := NewDistributedClaimsResolver(&DistributedClaimsResolverConfig{
		Enabled:           true,
		EndpointAllowlist: allowlist,
	})
	require.NoError(t, err)
	require.NotNil(t, r)
	return r
}

// fakeJWT builds a JWT-shaped string with the given JSON payload. The
// signature segment is intentionally junk; the resolver does not verify it.
func fakeJWT(payload string) string {
	enc := func(s string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(s))
	}
	return enc(`{"alg":"none"}`) + "." + enc(payload) + ".sig"
}

func TestDistributedClaimsResolver_DisabledReturnsNil(t *testing.T) {
	r, err := NewDistributedClaimsResolver(nil)
	require.NoError(t, err)
	require.Nil(t, r)

	r, err = NewDistributedClaimsResolver(&DistributedClaimsResolverConfig{Enabled: false})
	require.NoError(t, err)
	require.Nil(t, r)
}

func TestDistributedClaimsResolver_UsesEmbeddedAccessToken(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"groups":["g1","g2"]}`))
	}))
	defer srv.Close()

	r := newTestDistributedResolver(t, nil)
	claims := map[string]any{
		"_claim_names": map[string]any{"groups": "src1"},
		"_claim_sources": map[string]any{
			"src1": map[string]any{"endpoint": srv.URL, "access_token": "embedded"},
		},
	}
	r.Resolve(context.Background(), claims, &oauth2.Token{AccessToken: "user-token"})

	require.Equal(t, "Bearer embedded", gotAuth)
	require.Equal(t, []any{"g1", "g2"}, claims["groups"])
	require.NotContains(t, claims, "_claim_names")
	require.NotContains(t, claims, "_claim_sources")
}

func TestDistributedClaimsResolver_FallbackToUserToken(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"value":["g1"]}`))
	}))
	defer srv.Close()

	r := newTestDistributedResolver(t, nil)
	claims := map[string]any{
		"_claim_names": map[string]any{"groups": "src1"},
		"_claim_sources": map[string]any{
			"src1": map[string]any{"endpoint": srv.URL},
		},
	}
	r.Resolve(context.Background(), claims, &oauth2.Token{AccessToken: "user-token"})

	require.Equal(t, "Bearer user-token", gotAuth)
}

func TestDistributedClaimsResolver_NoAuthWhenNoTokens(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"groups":[]}`))
	}))
	defer srv.Close()

	r := newTestDistributedResolver(t, nil)
	claims := map[string]any{
		"_claim_names":   map[string]any{"groups": "src1"},
		"_claim_sources": map[string]any{"src1": map[string]any{"endpoint": srv.URL}},
	}
	r.Resolve(context.Background(), claims, nil)
	require.Equal(t, "", gotAuth)
}

func TestDistributedClaimsResolver_JWTResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte(fakeJWT(`{"groups":["jwt-grp"]}`)))
	}))
	defer srv.Close()

	r := newTestDistributedResolver(t, nil)
	claims := map[string]any{
		"_claim_names":   map[string]any{"groups": "src1"},
		"_claim_sources": map[string]any{"src1": map[string]any{"endpoint": srv.URL}},
	}
	r.Resolve(context.Background(), claims, &oauth2.Token{AccessToken: "t"})
	require.Equal(t, []any{"jwt-grp"}, claims["groups"])
}

func TestDistributedClaimsResolver_JSONResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"groups":["json-grp"]}`))
	}))
	defer srv.Close()

	r := newTestDistributedResolver(t, nil)
	claims := map[string]any{
		"_claim_names":   map[string]any{"groups": "src1"},
		"_claim_sources": map[string]any{"src1": map[string]any{"endpoint": srv.URL}},
	}
	r.Resolve(context.Background(), claims, &oauth2.Token{AccessToken: "t"})
	require.Equal(t, []any{"json-grp"}, claims["groups"])
}

func TestDistributedClaimsResolver_ValueArrayResponse(t *testing.T) {
	// Microsoft Graph /me/memberOf returns {"value":[...]} without echoing
	// the claim name. The resolver must fall back to the "value" key.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":["aad-1","aad-2"]}`))
	}))
	defer srv.Close()

	r := newTestDistributedResolver(t, nil)
	claims := map[string]any{
		"_claim_names":   map[string]any{"groups": "src1"},
		"_claim_sources": map[string]any{"src1": map[string]any{"endpoint": srv.URL}},
	}
	r.Resolve(context.Background(), claims, &oauth2.Token{AccessToken: "t"})
	require.Equal(t, []any{"aad-1", "aad-2"}, claims["groups"])
}

func TestDistributedClaimsResolver_AllowlistAccept(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"groups":["ok"]}`))
	}))
	defer srv.Close()

	// httptest URLs use 127.0.0.1; allow that suffix.
	r := newTestDistributedResolver(t, []string{"127.0.0.1"})
	claims := map[string]any{
		"_claim_names":   map[string]any{"groups": "src1"},
		"_claim_sources": map[string]any{"src1": map[string]any{"endpoint": srv.URL}},
	}
	r.Resolve(context.Background(), claims, &oauth2.Token{AccessToken: "t"})
	require.Equal(t, []any{"ok"}, claims["groups"])
}

func TestDistributedClaimsResolver_AllowlistReject(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_, _ = w.Write([]byte(`{"groups":["should-not-resolve"]}`))
	}))
	defer srv.Close()

	r := newTestDistributedResolver(t, []string{"graph.microsoft.com"})
	claims := map[string]any{
		"_claim_names":   map[string]any{"groups": "src1"},
		"_claim_sources": map[string]any{"src1": map[string]any{"endpoint": srv.URL}},
	}
	r.Resolve(context.Background(), claims, &oauth2.Token{AccessToken: "t"})

	require.False(t, called, "endpoint outside allowlist must not be called")
	require.NotContains(t, claims, "groups")
	// The unresolved reference is left in place so the caller can see what
	// happened in logs.
	require.Contains(t, claims, "_claim_names")
}

func TestDistributedClaimsResolver_AllowlistSubdomainSuffix(t *testing.T) {
	r := newTestDistributedResolver(t, []string{"graph.microsoft.com"})
	require.True(t, r.endpointAllowed("https://graph.microsoft.com/v1.0/me"))
	require.True(t, r.endpointAllowed("https://us.graph.microsoft.com/v1.0/me"))
	require.False(t, r.endpointAllowed("https://evil.com/?graph.microsoft.com=1"))
	require.False(t, r.endpointAllowed("https://graph.microsoft.com.evil.com/x"))
	require.False(t, r.endpointAllowed("ftp://graph.microsoft.com/x"))
	require.False(t, r.endpointAllowed("not a url"))
}

func TestDistributedClaimsResolver_BadEndpointSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"roles":["admin"]}`))
	}))
	defer srv.Close()

	r := newTestDistributedResolver(t, nil)
	claims := map[string]any{
		"_claim_names": map[string]any{
			"groups": "bad",
			"roles":  "good",
		},
		"_claim_sources": map[string]any{
			"bad":  map[string]any{"endpoint": "not-a-url"},
			"good": map[string]any{"endpoint": srv.URL},
		},
	}
	r.Resolve(context.Background(), claims, &oauth2.Token{AccessToken: "t"})

	require.Equal(t, []any{"admin"}, claims["roles"])
	require.NotContains(t, claims, "groups")
	// The bad source is still referenced; the good one was cleaned up.
	names := claims["_claim_names"].(map[string]any)
	require.Contains(t, names, "groups")
	require.NotContains(t, names, "roles")
}

func TestDistributedClaimsResolver_Non2xxSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()

	r := newTestDistributedResolver(t, nil)
	claims := map[string]any{
		"_claim_names":   map[string]any{"groups": "src1"},
		"_claim_sources": map[string]any{"src1": map[string]any{"endpoint": srv.URL}},
	}
	r.Resolve(context.Background(), claims, &oauth2.Token{AccessToken: "t"})

	require.NotContains(t, claims, "groups")
	require.Contains(t, claims, "_claim_names")
}

func TestDistributedClaimsResolver_BodySizeCapEnforced(t *testing.T) {
	huge := `{"groups":["` + strings.Repeat("a", maxDistributedClaimBodyBytes+10) + `"]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(huge))
	}))
	defer srv.Close()

	r := newTestDistributedResolver(t, nil)
	claims := map[string]any{
		"_claim_names":   map[string]any{"groups": "src1"},
		"_claim_sources": map[string]any{"src1": map[string]any{"endpoint": srv.URL}},
	}
	r.Resolve(context.Background(), claims, &oauth2.Token{AccessToken: "t"})
	require.NotContains(t, claims, "groups")
}

func TestDistributedClaimsResolver_AggregatedClaimSkipped(t *testing.T) {
	// Aggregated claims have a "JWT" key in the source. We don't handle
	// them (a future enhancement), but they must not crash the resolver
	// or block other distributed claims from being processed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"roles":["editor"]}`))
	}))
	defer srv.Close()

	r := newTestDistributedResolver(t, nil)
	claims := map[string]any{
		"_claim_names": map[string]any{
			"groups": "agg",
			"roles":  "dist",
		},
		"_claim_sources": map[string]any{
			"agg":  map[string]any{"JWT": "eyJhbGc..."},
			"dist": map[string]any{"endpoint": srv.URL},
		},
	}
	r.Resolve(context.Background(), claims, &oauth2.Token{AccessToken: "t"})

	require.Equal(t, []any{"editor"}, claims["roles"])
	require.NotContains(t, claims, "groups")
}

func TestDistributedClaimsResolver_NoOpWhenNoDistributedClaims(t *testing.T) {
	r := newTestDistributedResolver(t, nil)
	claims := map[string]any{"sub": "u1", "groups": []any{"g1"}}
	r.Resolve(context.Background(), claims, &oauth2.Token{AccessToken: "t"})
	require.Equal(t, []any{"g1"}, claims["groups"])
}

func TestDistributedClaimsResolver_AllowlistNormalizesCase(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"groups":["g"]}`))
	}))
	defer srv.Close()

	// Mixed-case allowlist entry should still match the lowercase host.
	r := newTestDistributedResolver(t, []string{"  127.0.0.1  ", "GRAPH.Microsoft.com"})
	claims := map[string]any{
		"_claim_names":   map[string]any{"groups": "src1"},
		"_claim_sources": map[string]any{"src1": map[string]any{"endpoint": srv.URL}},
	}
	r.Resolve(context.Background(), claims, &oauth2.Token{AccessToken: "t"})
	require.Equal(t, []any{"g"}, claims["groups"])
}
