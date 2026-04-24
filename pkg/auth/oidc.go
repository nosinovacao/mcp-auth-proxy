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
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gobwas/glob"
	"github.com/mattn/go-jsonpointer"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type oidcProvider struct {
	oauth2                oauth2.Config
	providerName          string
	userInfoURL           string
	userIDField           string
	allowedUsers          []string
	allowedUsersGlob      []glob.Glob
	allowedAttributes     map[string][]string
	allowedAttributesGlob map[string][]glob.Glob
	allowedGroups         []string
	graphAPIEndpoint      string
	graphTokenSource      oauth2.TokenSource
	graphHTTPClient       *http.Client
	graphLogger           *zap.Logger
}

func NewOIDCProvider(
	configurationURL string, scopes []string, userIDField string,
	providerName, externalURL, clientID, clientSecret string, allowedUsers []string, allowedUsersGlob []string,
	allowedAttributes map[string][]string, allowedAttributesGlob map[string][]string,
	allowedGroups []string, graphAPIEndpoint string, logger *zap.Logger,
) (Provider, error) {
	resp, err := http.Get(configurationURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("OIDC configuration request failed: %s", resp.Status)
	}
	var cfg struct {
		AuthEndpoint  string `json:"authorization_endpoint"`
		TokenEndpoint string `json:"token_endpoint"`
		UserInfo      string `json:"userinfo_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, err
	}
	r, err := url.JoinPath(externalURL, OIDCCallbackEndpoint)
	if err != nil {
		return nil, err
	}

	// Compile glob patterns
	var compiledGlobs []glob.Glob
	for _, pattern := range allowedUsersGlob {
		if pattern != "" {
			g, err := glob.Compile(pattern)
			if err != nil {
				return nil, err
			}
			compiledGlobs = append(compiledGlobs, g)
		}
	}

	// Compile attribute glob patterns
	compiledAttributeGlobs := make(map[string][]glob.Glob)
	for key, patterns := range allowedAttributesGlob {
		for _, pattern := range patterns {
			if pattern != "" {
				g, err := glob.Compile(pattern)
				if err != nil {
					return nil, err
				}
				compiledAttributeGlobs[key] = append(compiledAttributeGlobs[key], g)
			}
		}
	}

	p := &oidcProvider{
		oauth2: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  r,
			Scopes:       scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  cfg.AuthEndpoint,
				TokenURL: cfg.TokenEndpoint,
			},
		},
		providerName:          providerName,
		userInfoURL:           cfg.UserInfo,
		userIDField:           userIDField,
		allowedUsers:          allowedUsers,
		allowedUsersGlob:      compiledGlobs,
		allowedAttributes:     allowedAttributes,
		allowedAttributesGlob: compiledAttributeGlobs,
	}

	if len(allowedGroups) > 0 {
		normalizedEndpoint := strings.TrimRight(graphAPIEndpoint, "/")
		if _, err := url.Parse(normalizedEndpoint); err != nil || normalizedEndpoint == "" {
			return nil, fmt.Errorf("invalid graph API endpoint %q: must be a non-empty URL when allowed groups are configured", graphAPIEndpoint)
		}
		// Bound token-endpoint HTTP calls so a stalled IdP can't wedge the
		// auth flow. The TokenSource caches tokens across requests, so this
		// only trips on initial fetch or refresh.
		tokenHTTPClient := &http.Client{Timeout: 10 * time.Second}
		tokenCtx := context.WithValue(context.Background(), oauth2.HTTPClient, tokenHTTPClient)
		ccConfig := clientcredentials.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			TokenURL:     cfg.TokenEndpoint,
			Scopes:       []string{normalizedEndpoint + "/.default"},
		}
		p.graphTokenSource = ccConfig.TokenSource(tokenCtx)
		p.allowedGroups = allowedGroups
		p.graphAPIEndpoint = normalizedEndpoint
		p.graphHTTPClient = http.DefaultClient
		if logger != nil {
			p.graphLogger = logger
		} else {
			p.graphLogger = zap.NewNop()
		}
	}

	return p, nil
}

func (p *oidcProvider) Name() string {
	return p.providerName
}

func (p *oidcProvider) Type() string {
	return "oidc"
}

func (p *oidcProvider) RedirectURL() string {
	return OIDCCallbackEndpoint
}

func (p *oidcProvider) AuthURL() string {
	return OIDCAuthEndpoint
}

func (p *oidcProvider) AuthCodeURL(state string) (string, error) {
	authURL := p.oauth2.AuthCodeURL(state)
	return authURL, nil
}

func (p *oidcProvider) Exchange(c *gin.Context, state string) (*oauth2.Token, error) {
	if c.Query("state") != state {
		return nil, errors.New("invalid OAuth state")
	}
	code := c.Query("code")
	token, err := p.oauth2.Exchange(c, code)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (p *oidcProvider) Authorization(ctx context.Context, token *oauth2.Token) (bool, string, map[string]any, error) {
	client := p.oauth2.Client(ctx, token)
	resp, err := client.Get(p.userInfoURL)
	if err != nil {
		return false, "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return false, "", nil, fmt.Errorf("userinfo request failed: %s", resp.Status)
	}
	var obj any
	if err := json.NewDecoder(resp.Body).Decode(&obj); err != nil {
		return false, "", nil, err
	}
	userInfoMap, ok := obj.(map[string]any)
	if !ok {
		return false, "", nil, errors.New("userinfo response is not a JSON object")
	}
	v, err := jsonpointer.Get(obj, p.userIDField)
	if err != nil {
		return false, "", nil, err
	}
	userID, ok := v.(string)
	if !ok {
		return false, "", nil, errors.New("user ID field is not a string")
	}

	// If no restrictions are set, allow all users
	if len(p.allowedUsers) == 0 && len(p.allowedUsersGlob) == 0 &&
		len(p.allowedAttributes) == 0 && len(p.allowedAttributesGlob) == 0 &&
		len(p.allowedGroups) == 0 {
		return true, userID, userInfoMap, nil
	}

	// Check exact user matches first
	if slices.Contains(p.allowedUsers, userID) {
		return true, userID, userInfoMap, nil
	}

	// Check user glob patterns
	for _, g := range p.allowedUsersGlob {
		if g.Match(userID) {
			return true, userID, userInfoMap, nil
		}
	}

	// Check exact attribute matches
	for key, allowedValues := range p.allowedAttributes {
		attrValue, err := jsonpointer.Get(obj, key)
		if err != nil {
			continue // Attribute not found, skip
		}
		if matchAttributeValue(attrValue, allowedValues) {
			return true, userID, userInfoMap, nil
		}
	}

	// Check attribute glob patterns
	for key, globs := range p.allowedAttributesGlob {
		attrValue, err := jsonpointer.Get(obj, key)
		if err != nil {
			continue // Attribute not found, skip
		}
		if matchAttributeGlob(attrValue, globs) {
			return true, userID, userInfoMap, nil
		}
	}

	// Graph API group membership check
	if len(p.allowedGroups) > 0 {
		allowed, err := p.checkGraphAPIGroups(ctx, userInfoMap)
		if err != nil {
			p.graphLogger.Error("Graph API group check failed", zap.Error(err))
			return false, userID, userInfoMap, nil // fail closed
		}
		if allowed {
			return true, userID, userInfoMap, nil
		}
	}

	return false, userID, userInfoMap, nil
}

func (p *oidcProvider) checkGraphAPIGroups(ctx context.Context, userInfoMap map[string]any) (bool, error) {
	oid := ""
	if v, err := jsonpointer.Get(userInfoMap, "/oid"); err == nil {
		oid = fmt.Sprintf("%v", v)
	} else if v, err := jsonpointer.Get(userInfoMap, "/sub"); err == nil {
		oid = fmt.Sprintf("%v", v)
	}
	if oid == "" {
		return false, errors.New("user object ID (oid/sub) not found in userinfo")
	}

	token, err := p.graphTokenSource.Token()
	if err != nil {
		return false, fmt.Errorf("failed to get Graph API token: %w", err)
	}

	reqBody := map[string]any{"groupIds": p.allowedGroups}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return false, fmt.Errorf("failed to marshal request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v1.0/users/%s/checkMemberGroups", p.graphAPIEndpoint, url.PathEscape(oid))
	httpCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(httpCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	client := p.graphHTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("Graph API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("Graph API returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Value []string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("failed to decode Graph API response: %w", err)
	}

	return len(result.Value) > 0, nil
}

// matchAttributeValue checks if an attribute value matches any of the allowed values.
// Supports string values and arrays of strings.
func matchAttributeValue(attrValue any, allowedValues []string) bool {
	switch v := attrValue.(type) {
	case string:
		return slices.Contains(allowedValues, v)
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				if slices.Contains(allowedValues, s) {
					return true
				}
			}
		}
	}
	return false
}

// matchAttributeGlob checks if an attribute value matches any of the glob patterns.
// Supports string values and arrays of strings.
func matchAttributeGlob(attrValue any, globs []glob.Glob) bool {
	switch v := attrValue.(type) {
	case string:
		for _, g := range globs {
			if g.Match(v) {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				for _, g := range globs {
					if g.Match(s) {
						return true
					}
				}
			}
		}
	}
	return false
}
