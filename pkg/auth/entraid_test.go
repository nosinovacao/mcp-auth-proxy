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
		httpClient:       http.DefaultClient,
	}
}

func userToken() *oauth2.Token {
	return &oauth2.Token{AccessToken: "user-access-token"}
}

func TestEntraIDGroupResolver_Allowed(t *testing.T) {
	var gotBody map[string]any
	var gotAuth string
	var gotPath string
	var gotMethod string
	var readErr, unmarshalErr error
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotMethod = r.Method
		var body []byte
		body, readErr = io.ReadAll(r.Body)
		unmarshalErr = json.Unmarshal(body, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// User belongs to group-1 plus an unrelated directory role.
		_, _ = w.Write([]byte(`{"value":["group-1","00000000-0000-0000-0000-000000000001"]}`))
	}))
	defer srv.Close()

	r := newTestEntraIDResolver(t, srv.URL, []string{"group-1", "group-2"})

	allowed, err := r.Check(context.Background(), userToken())
	require.NoError(t, err)
	require.NoError(t, readErr)
	require.NoError(t, unmarshalErr)
	require.True(t, allowed)
	require.Equal(t, "Bearer user-access-token", gotAuth)
	require.Equal(t, http.MethodPost, gotMethod)
	require.Equal(t, "/v1.0/me/getMemberObjects", gotPath)
	require.Equal(t, false, gotBody["securityEnabledOnly"])
}

func TestEntraIDGroupResolver_Denied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// User has memberships, but none match the allow-list.
		_, _ = w.Write([]byte(`{"value":["other-group","another-group"]}`))
	}))
	defer srv.Close()

	r := newTestEntraIDResolver(t, srv.URL, []string{"group-1"})

	allowed, err := r.Check(context.Background(), userToken())
	require.NoError(t, err)
	require.False(t, allowed)
}

func TestEntraIDGroupResolver_DeniedEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	defer srv.Close()

	r := newTestEntraIDResolver(t, srv.URL, []string{"group-1"})

	allowed, err := r.Check(context.Background(), userToken())
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

	allowed, err := r.Check(context.Background(), userToken())
	require.Error(t, err)
	require.False(t, allowed)
}

func TestEntraIDGroupResolver_MissingToken(t *testing.T) {
	r := newTestEntraIDResolver(t, "http://unused", []string{"group-1"})

	allowed, err := r.Check(context.Background(), nil)
	require.Error(t, err)
	require.False(t, allowed)

	allowed, err = r.Check(context.Background(), &oauth2.Token{})
	require.Error(t, err)
	require.False(t, allowed)
}

func TestNewEntraIDGroupResolver_DisabledWhenEmpty(t *testing.T) {
	// nil or empty AllowedGroups returns (nil, nil) so callers don't
	// have to special-case the unset path.
	r, err := NewEntraIDGroupResolver(nil)
	require.NoError(t, err)
	require.Nil(t, r)

	r, err = NewEntraIDGroupResolver(&EntraIDGroupResolverConfig{})
	require.NoError(t, err)
	require.Nil(t, r)
}

func TestNewEntraIDGroupResolver_RejectsBadEndpoint(t *testing.T) {
	cases := []struct {
		name     string
		endpoint string
	}{
		{"empty", ""},
		{"whitespace only", "   "},
		{"relative", "graph.microsoft.com"},
		{"missing host", "https://"},
		{"unsupported scheme", "ftp://graph.microsoft.com"},
		{"with path", "https://graph.microsoft.com/v1.0"},
		{"with deep path", "https://graph.microsoft.com/v1.0/users"},
		{"with query", "https://graph.microsoft.com?api-version=1.0"},
		{"with fragment", "https://graph.microsoft.com#section"},
		{"with path and query", "https://graph.microsoft.com/v1.0?foo=bar"},
		{"with path query and fragment", "https://graph.microsoft.com/v1.0?foo=bar#frag"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewEntraIDGroupResolver(&EntraIDGroupResolverConfig{
				AllowedGroups:    []string{"group-1"},
				GraphAPIEndpoint: tc.endpoint,
			})
			require.Error(t, err)
		})
	}
}

func TestNewEntraIDGroupResolver_TrimsTrailingSlash(t *testing.T) {
	r, err := NewEntraIDGroupResolver(&EntraIDGroupResolverConfig{
		AllowedGroups:    []string{"group-1"},
		GraphAPIEndpoint: "https://graph.microsoft.com/",
	})
	require.NoError(t, err)
	require.NotNil(t, r)
	require.Equal(t, "https://graph.microsoft.com", r.graphAPIEndpoint)
}

func TestNewEntraIDGroupResolver_TrimsWhitespace(t *testing.T) {
	r, err := NewEntraIDGroupResolver(&EntraIDGroupResolverConfig{
		AllowedGroups:    []string{"group-1"},
		GraphAPIEndpoint: "  https://graph.microsoft.com  ",
	})
	require.NoError(t, err)
	require.NotNil(t, r)
	require.Equal(t, "https://graph.microsoft.com", r.graphAPIEndpoint)
}

func TestNewEntraIDGroupResolver_AcceptsValidEndpoints(t *testing.T) {
	cases := []struct {
		name       string
		endpoint   string
		normalized string
	}{
		{"https bare", "https://graph.microsoft.com", "https://graph.microsoft.com"},
		{"https trailing slash", "https://graph.microsoft.com/", "https://graph.microsoft.com"},
		{"http bare", "http://localhost:8080", "http://localhost:8080"},
		{"http trailing slash", "http://localhost:8080/", "http://localhost:8080"},
		{"with port", "https://graph.microsoft.com:443", "https://graph.microsoft.com:443"},
		{"whitespace padded with slash", "  https://graph.microsoft.com/  ", "https://graph.microsoft.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewEntraIDGroupResolver(&EntraIDGroupResolverConfig{
				AllowedGroups:    []string{"group-1"},
				GraphAPIEndpoint: tc.endpoint,
			})
			require.NoError(t, err)
			require.NotNil(t, r)
			require.Equal(t, tc.normalized, r.graphAPIEndpoint)
		})
	}
}
