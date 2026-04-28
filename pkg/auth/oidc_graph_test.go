package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func newGraphProvider(t *testing.T, endpoint string, allowedGroups []string) *oidcProvider {
	t.Helper()
	return &oidcProvider{
		allowedGroups:    allowedGroups,
		graphAPIEndpoint: endpoint,
		graphTokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}),
		graphHTTPClient:  http.DefaultClient,
	}
}

func TestCheckGraphAPIGroups_Allowed(t *testing.T) {
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

	p := newGraphProvider(t, srv.URL, []string{"group-1", "group-2"})
	userInfo := map[string]any{"oid": "user-oid-123"}

	allowed, err := p.checkGraphAPIGroups(context.Background(), userInfo)
	require.NoError(t, err)
	require.NoError(t, readErr)
	require.NoError(t, unmarshalErr)
	require.True(t, allowed)
	require.Equal(t, "Bearer test-token", gotAuth)
	require.Equal(t, "/v1.0/users/user-oid-123/checkMemberGroups", gotPath)
	require.ElementsMatch(t, []any{"group-1", "group-2"}, gotBody["groupIds"])
}

func TestCheckGraphAPIGroups_NonStringOID(t *testing.T) {
	p := newGraphProvider(t, "http://unused", []string{"group-1"})
	// Azure AD token endpoints can return nulls or unexpected types for
	// claims; with no usable oid/sub we must not stringify them into a
	// bogus user lookup.
	allowed, err := p.checkGraphAPIGroups(context.Background(), map[string]any{"oid": nil})
	require.Error(t, err)
	require.False(t, allowed)
}

func TestCheckGraphAPIGroups_InvalidOIDFallsBackToSub(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"value":["group-1"]}`))
	}))
	defer srv.Close()

	p := newGraphProvider(t, srv.URL, []string{"group-1"})
	// A present-but-invalid /oid (null) must not mask a usable /sub.
	userInfo := map[string]any{"oid": nil, "sub": "user-sub-789"}

	allowed, err := p.checkGraphAPIGroups(context.Background(), userInfo)
	require.NoError(t, err)
	require.True(t, allowed)
	require.Equal(t, "/v1.0/users/user-sub-789/checkMemberGroups", gotPath)
}

func TestCheckGraphAPIGroups_Denied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	defer srv.Close()

	p := newGraphProvider(t, srv.URL, []string{"group-1"})
	userInfo := map[string]any{"oid": "user-oid-123"}

	allowed, err := p.checkGraphAPIGroups(context.Background(), userInfo)
	require.NoError(t, err)
	require.False(t, allowed)
}

func TestCheckGraphAPIGroups_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()

	p := newGraphProvider(t, srv.URL, []string{"group-1"})
	userInfo := map[string]any{"oid": "user-oid-123"}

	allowed, err := p.checkGraphAPIGroups(context.Background(), userInfo)
	require.Error(t, err)
	require.False(t, allowed)
}

func TestCheckGraphAPIGroups_MissingOID(t *testing.T) {
	p := newGraphProvider(t, "http://unused", []string{"group-1"})
	allowed, err := p.checkGraphAPIGroups(context.Background(), map[string]any{})
	require.Error(t, err)
	require.False(t, allowed)
}

func TestCheckGraphAPIGroups_FallsBackToSub(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"value":["group-1"]}`))
	}))
	defer srv.Close()

	p := newGraphProvider(t, srv.URL, []string{"group-1"})
	userInfo := map[string]any{"sub": "user-sub-456"}

	allowed, err := p.checkGraphAPIGroups(context.Background(), userInfo)
	require.NoError(t, err)
	require.True(t, allowed)
	require.Equal(t, "/v1.0/users/user-sub-456/checkMemberGroups", gotPath)
}

func TestAuthorization_GraphAPIDisabled(t *testing.T) {
	// When allowedGroups is empty, the Graph API check must be skipped
	// entirely — even if the user would otherwise be denied, no outbound
	// request is made. A nil graphTokenSource would panic if called.
	p, _, userinfo, tsConfig := setupOIDCTest([]string{"other@example.com"}, "/email")
	defer tsConfig.Close()

	userinfo.GET("/userinfo", func(c *gin.Context) {
		c.JSON(http.StatusOK, map[string]any{"sub": "u1", "email": "denied@example.com"})
	})

	op := p.(*oidcProvider)
	require.Empty(t, op.allowedGroups)
	require.Nil(t, op.graphTokenSource)

	allowed, _, _, err := p.Authorization(context.Background(), &oauth2.Token{AccessToken: "t"})
	require.NoError(t, err)
	require.False(t, allowed)
}
