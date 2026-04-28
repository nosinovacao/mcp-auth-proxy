package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mattn/go-jsonpointer"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
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
// Microsoft Graph API using OAuth client credentials.
type entraIDGroupResolver struct {
	allowedGroups    []string
	graphAPIEndpoint string
	tokenSource      oauth2.TokenSource
	httpClient       *http.Client
	logger           *zap.Logger
}

// NewEntraIDGroupResolver validates the config and constructs a resolver
// bound to the OIDC token endpoint discovered by the caller. Returns
// (nil, nil) when cfg is nil or has no allowed groups, so the caller does
// not need to special-case the disabled path.
func NewEntraIDGroupResolver(
	cfg *EntraIDGroupResolverConfig,
	tokenEndpoint, clientID, clientSecret string,
) (*entraIDGroupResolver, error) {
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
	// Bound token-endpoint HTTP calls so a stalled IdP can't wedge the
	// auth flow. The TokenSource caches tokens across requests, so this
	// only trips on initial fetch or refresh.
	tokenHTTPClient := &http.Client{Timeout: 10 * time.Second}
	tokenCtx := context.WithValue(context.Background(), oauth2.HTTPClient, tokenHTTPClient)
	ccConfig := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tokenEndpoint,
		Scopes:       []string{normalizedEndpoint + "/.default"},
	}
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	return &entraIDGroupResolver{
		allowedGroups:    cfg.AllowedGroups,
		graphAPIEndpoint: normalizedEndpoint,
		tokenSource:      ccConfig.TokenSource(tokenCtx),
		httpClient:       http.DefaultClient,
		logger:           logger,
	}, nil
}

// Check returns true if the user identified by userInfoMap belongs to at
// least one of the configured groups. On error, the caller should treat
// the result as a denial (fail closed) and use the resolver's logger to
// surface the cause.
func (r *entraIDGroupResolver) Check(ctx context.Context, userInfoMap map[string]any) (bool, error) {
	oid, err := graphUserID(userInfoMap)
	if err != nil {
		return false, err
	}

	token, err := r.tokenSource.Token()
	if err != nil {
		return false, fmt.Errorf("failed to get Graph API token: %w", err)
	}

	reqBody := map[string]any{"groupIds": r.allowedGroups}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return false, fmt.Errorf("failed to marshal request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v1.0/users/%s/checkMemberGroups", r.graphAPIEndpoint, url.PathEscape(oid))
	httpCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(httpCtx, http.MethodPost, endpoint, bytes.NewReader(body))
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

	return len(result.Value) > 0, nil
}

// graphUserID returns the Entra ID object ID to use for Graph lookups,
// preferring /oid and falling back to /sub. A claim that is missing,
// non-string, or an empty string is skipped so that a present-but-invalid
// /oid (e.g. null) doesn't block a usable /sub from being tried.
func graphUserID(userInfoMap map[string]any) (string, error) {
	for _, pointer := range []string{"/oid", "/sub"} {
		v, err := jsonpointer.Get(userInfoMap, pointer)
		if err != nil {
			continue
		}
		s, ok := v.(string)
		if !ok || s == "" {
			continue
		}
		return s, nil
	}
	return "", errors.New("user object ID (oid/sub) not found in userinfo")
}
