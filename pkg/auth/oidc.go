package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gobwas/glob"
	"github.com/mattn/go-jsonpointer"
	"golang.org/x/oauth2"
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
	distributedClaims     *distributedClaimsResolver
}

func NewOIDCProvider(
	configurationURL string, scopes []string, userIDField string,
	providerName, externalURL, clientID, clientSecret string, allowedUsers []string, allowedUsersGlob []string,
	allowedAttributes map[string][]string, allowedAttributesGlob map[string][]string,
	distributedClaimsConfig *DistributedClaimsResolverConfig,
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

	resolver, err := NewDistributedClaimsResolver(distributedClaimsConfig)
	if err != nil {
		return nil, err
	}

	return &oidcProvider{
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
		distributedClaims:     resolver,
	}, nil
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

	// Distributed claims (OIDC Core 1.0 §5.6.2) often appear in the ID
	// token rather than userinfo (notably for Entra ID's group-overage
	// case), so merge ID-token claims into userInfoMap before running the
	// distributed-claims resolver and the attribute filters. Userinfo wins
	// on conflict — it's the authoritative profile endpoint.
	if p.distributedClaims != nil {
		if idTokenClaims := decodeIDTokenClaims(token); idTokenClaims != nil {
			for k, v := range idTokenClaims {
				if _, exists := userInfoMap[k]; !exists {
					userInfoMap[k] = v
				}
			}
		}
		p.distributedClaims.Resolve(ctx, userInfoMap, token)
	}

	// If no restrictions are set, allow all users
	if len(p.allowedUsers) == 0 && len(p.allowedUsersGlob) == 0 &&
		len(p.allowedAttributes) == 0 && len(p.allowedAttributesGlob) == 0 {
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
		attrValue, err := jsonpointer.Get(userInfoMap, key)
		if err != nil {
			continue // Attribute not found, skip
		}
		if matchAttributeValue(attrValue, allowedValues) {
			return true, userID, userInfoMap, nil
		}
	}

	// Check attribute glob patterns
	for key, globs := range p.allowedAttributesGlob {
		attrValue, err := jsonpointer.Get(userInfoMap, key)
		if err != nil {
			continue // Attribute not found, skip
		}
		if matchAttributeGlob(attrValue, globs) {
			return true, userID, userInfoMap, nil
		}
	}

	return false, userID, userInfoMap, nil
}

// decodeIDTokenClaims extracts the payload of the ID token if one is
// present in the OAuth2 token's extras. The signature is not verified — the
// token came back over a TLS-protected channel from the configured OIDC
// provider, and this code only reads claims; it doesn't trust them for
// authentication on its own. Returns nil if the ID token is absent or
// malformed; callers must treat that as "no extra claims available".
func decodeIDTokenClaims(token *oauth2.Token) map[string]any {
	if token == nil {
		return nil
	}
	rawAny := token.Extra("id_token")
	raw, ok := rawAny.(string)
	if !ok || raw == "" {
		return nil
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}
	return claims
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
