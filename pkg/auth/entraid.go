package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// EntraIDGroupResolverConfig is the user-supplied configuration for the
// Entra ID group-membership check. NewOIDCProvider materializes a resolver
// from this config after discovering the OIDC token endpoint.
type EntraIDGroupResolverConfig struct {
	AllowedGroups    []string
	GraphAPIEndpoint string
	Logger           *zap.Logger
}

// entraIDGroupResolver checks Microsoft Entra ID group membership via the
// Microsoft Graph API using the signed-in user's delegated access token —
// the same approach Grafana takes when force_use_graph_api is enabled. The
// app registration only needs the delegated User.Read scope the user
// already consents to at sign-in; no admin-granted application permission
// is required.
type entraIDGroupResolver struct {
	allowedGroups    []string
	graphAPIEndpoint string
	httpClient       *http.Client
	logger           *zap.Logger
}

// NewEntraIDGroupResolver validates the config and constructs a resolver.
// Returns (nil, nil) when cfg is nil or has no allowed groups, so the
// caller does not need to special-case the disabled path.
func NewEntraIDGroupResolver(cfg *EntraIDGroupResolverConfig) (*entraIDGroupResolver, error) {
	if cfg == nil || len(cfg.AllowedGroups) == 0 {
		return nil, nil
	}
	trimmedEndpoint := strings.TrimSpace(cfg.GraphAPIEndpoint)
	parsedEndpoint, err := url.Parse(trimmedEndpoint)
	if trimmedEndpoint == "" || err != nil || !parsedEndpoint.IsAbs() ||
		parsedEndpoint.Host == "" ||
		(parsedEndpoint.Scheme != "http" && parsedEndpoint.Scheme != "https") ||
		(parsedEndpoint.Path != "" && parsedEndpoint.Path != "/") ||
		parsedEndpoint.RawQuery != "" ||
		parsedEndpoint.Fragment != "" {
		return nil, fmt.Errorf("invalid graph API endpoint %q: must be an absolute http(s) base URL with a host and no path, query, or fragment when allowed groups are configured", cfg.GraphAPIEndpoint)
	}
	normalizedEndpoint := parsedEndpoint.Scheme + "://" + parsedEndpoint.Host
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	return &entraIDGroupResolver{
		allowedGroups:    cfg.AllowedGroups,
		graphAPIEndpoint: normalizedEndpoint,
		httpClient:       http.DefaultClient,
		logger:           logger,
	}, nil
}

// Check returns true if the signed-in user belongs to at least one of the
// configured groups. It calls /me/getMemberObjects with the user's access
// token (delegated User.Read), then intersects the returned object IDs
// with the allow-list locally — so the proxy never needs to read groups
// for any user other than the one signing in. On error, the caller should
// treat the result as a denial (fail closed) and use the resolver's
// logger to surface the cause.
func (r *entraIDGroupResolver) Check(ctx context.Context, token *oauth2.Token) (bool, error) {
	if token == nil || token.AccessToken == "" {
		return false, fmt.Errorf("missing user access token")
	}

	reqBody, err := json.Marshal(map[string]any{"securityEnabledOnly": false})
	if err != nil {
		return false, fmt.Errorf("failed to marshal request: %w", err)
	}

	endpoint := r.graphAPIEndpoint + "/v1.0/me/getMemberObjects"
	httpCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(httpCtx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	client := r.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("graph API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Bound the body we keep for the error message so a large or
		// malicious response can't blow up memory or log lines.
		const maxGraphAPIErrorBodyBytes = 4096
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxGraphAPIErrorBodyBytes))
		respBodyText := string(respBody)
		if len(respBody) == maxGraphAPIErrorBodyBytes {
			respBodyText += "...(truncated)"
		}
		return false, fmt.Errorf("graph API returned %d: %s", resp.StatusCode, respBodyText)
	}

	var result struct {
		Value []string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("failed to decode Graph API response: %w", err)
	}

	for _, id := range result.Value {
		if slices.Contains(r.allowedGroups, id) {
			return true, nil
		}
	}
	return false, nil
}
