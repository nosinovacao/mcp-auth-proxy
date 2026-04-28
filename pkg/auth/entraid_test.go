package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func newTestEntraIDResolver(t *testing.T, endpoint string, allowedGroups []string) *entraIDGroupResolver {
	t.Helper()
	return &entraIDGroupResolver{
		allowedGroups:    allowedGroups,
		graphAPIEndpoint: endpoint,
		tokenSource:      oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}),
		httpClient:       http.DefaultClient,
	}
}

func TestEntraIDGroupResolver_Allowed(t *testing.T) {
	var gotBody map[string]any
	var gotAuth string
	var gotPath string
	var readErr, unmarshalErr error
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		var body []byte
		body, readErr = io.ReadAll(r.Body)
		unmarshalErr = json.Unmarshal(body, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"value":["group-1"]}`))
	}))
	defer srv.Close()

	r := newTestEntraIDResolver(t, srv.URL, []string{"group-1", "group-2"})
	userInfo := map[string]any{"oid": "user-oid-123"}

	allowed, err := r.Check(context.Background(), userInfo)
	require.NoError(t, err)
	require.NoError(t, readErr)
	require.NoError(t, unmarshalErr)
	require.True(t, allowed)
	require.Equal(t, "Bearer test-token", gotAuth)
	require.Equal(t, "/v1.0/users/user-oid-123/checkMemberGroups", gotPath)
	require.ElementsMatch(t, []any{"group-1", "group-2"}, gotBody["groupIds"])
}

func TestEntraIDGroupResolver_Denied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	defer srv.Close()

	r := newTestEntraIDResolver(t, srv.URL, []string{"group-1"})
	userInfo := map[string]any{"oid": "user-oid-123"}

	allowed, err := r.Check(context.Background(), userInfo)
	require.NoError(t, err)
	require.False(t, allowed)
}

func TestEntraIDGroupResolver_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()

	r := newTestEntraIDResolver(t, srv.URL, []string{"group-1"})
	userInfo := map[string]any{"oid": "user-oid-123"}

	allowed, err := r.Check(context.Background(), userInfo)
	require.Error(t, err)
	require.False(t, allowed)
}

func TestEntraIDGroupResolver_MissingOID(t *testing.T) {
	r := newTestEntraIDResolver(t, "http://unused", []string{"group-1"})
	allowed, err := r.Check(context.Background(), map[string]any{})
	require.Error(t, err)
	require.False(t, allowed)
}

func TestEntraIDGroupResolver_FallsBackToSub(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"value":["group-1"]}`))
	}))
	defer srv.Close()

	r := newTestEntraIDResolver(t, srv.URL, []string{"group-1"})
	userInfo := map[string]any{"sub": "user-sub-456"}

	allowed, err := r.Check(context.Background(), userInfo)
	require.NoError(t, err)
	require.True(t, allowed)
	require.Equal(t, "/v1.0/users/user-sub-456/checkMemberGroups", gotPath)
}

func TestEntraIDGroupResolver_NonStringOID(t *testing.T) {
	r := newTestEntraIDResolver(t, "http://unused", []string{"group-1"})
	// Token endpoints can return nulls or unexpected types for claims;
	// with no usable oid/sub we must not stringify them into a bogus
	// user lookup.
	allowed, err := r.Check(context.Background(), map[string]any{"oid": nil})
	require.Error(t, err)
	require.False(t, allowed)
}

func TestEntraIDGroupResolver_InvalidOIDFallsBackToSub(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"value":["group-1"]}`))
	}))
	defer srv.Close()

	r := newTestEntraIDResolver(t, srv.URL, []string{"group-1"})
	// A present-but-invalid /oid (null) must not mask a usable /sub.
	userInfo := map[string]any{"oid": nil, "sub": "user-sub-789"}

	allowed, err := r.Check(context.Background(), userInfo)
	require.NoError(t, err)
	require.True(t, allowed)
	require.Equal(t, "/v1.0/users/user-sub-789/checkMemberGroups", gotPath)
}

func TestNewEntraIDGroupResolver_DisabledWhenEmpty(t *testing.T) {
	// nil or empty AllowedGroups returns (nil, nil) so callers don't
	// have to special-case the unset path.
	r, err := NewEntraIDGroupResolver(nil, "https://login.example/token", "id", "secret")
	require.NoError(t, err)
	require.Nil(t, r)

	r, err = NewEntraIDGroupResolver(&EntraIDGroupResolverConfig{}, "https://login.example/token", "id", "secret")
	require.NoError(t, err)
	require.Nil(t, r)
}

func TestNewEntraIDGroupResolver_RejectsBadEndpoint(t *testing.T) {
	cases := []struct {
		name     string
		endpoint string
	}{
		{"empty", ""},
		{"relative", "graph.microsoft.com"},
		{"missing host", "https://"},
		{"unsupported scheme", "ftp://graph.microsoft.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewEntraIDGroupResolver(&EntraIDGroupResolverConfig{
				AllowedGroups:    []string{"group-1"},
				GraphAPIEndpoint: tc.endpoint,
			}, "https://login.example/token", "id", "secret")
			require.Error(t, err)
		})
	}
}

func TestNewEntraIDGroupResolver_TrimsTrailingSlash(t *testing.T) {
	r, err := NewEntraIDGroupResolver(&EntraIDGroupResolverConfig{
		AllowedGroups:    []string{"group-1"},
		GraphAPIEndpoint: "https://graph.microsoft.com/",
	}, "https://login.example/token", "id", "secret")
	require.NoError(t, err)
	require.NotNil(t, r)
	require.Equal(t, "https://graph.microsoft.com", r.graphAPIEndpoint)
}
