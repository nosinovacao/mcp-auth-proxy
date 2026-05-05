package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// Cap on resolved-claim response bodies. The OIDC spec doesn't bound them,
// but a malicious or misconfigured endpoint could otherwise pin arbitrary
// memory. 1 MiB is enough for tens of thousands of group IDs.
const maxDistributedClaimBodyBytes = 1 << 20

// Per-source HTTP timeout. Matches the value used elsewhere in pkg/auth.
const distributedClaimHTTPTimeout = 10 * time.Second

// DistributedClaimsResolverConfig is the user-supplied configuration for the
// OIDC distributed-claims resolver (OIDC Core 1.0 §5.6.2). NewOIDCProvider
// materializes a resolver from this config when distributed-claims handling
// is enabled.
type DistributedClaimsResolverConfig struct {
	// Enabled gates the entire resolver. When false, NewDistributedClaimsResolver
	// returns (nil, nil) so callers can skip the distributed-claims branch
	// without a special-case.
	Enabled bool
	// EndpointAllowlist, if non-empty, restricts which endpoint hosts the
	// resolver will dereference. Each entry is matched as a host suffix
	// against the URL's host (e.g. "graph.microsoft.com" matches
	// "graph.microsoft.com" and "foo.graph.microsoft.com"). When empty, any
	// host is accepted; admins should set this to the specific hosts their
	// IdP advertises to defend against SSRF via crafted tokens.
	EndpointAllowlist []string
	HTTPClient        *http.Client
	Logger            *zap.Logger
}

// distributedClaimsResolver dereferences OIDC distributed claims by GET-ing
// the endpoint advertised in `_claim_sources`, with the access token from
// the source if present, otherwise the user's own delegated token. The
// response body is parsed as either a JWT (per spec) or a plain JSON object
// (the form Microsoft Graph returns when used as an EntraID claim source).
//
// JWT signature verification is intentionally NOT performed in this
// resolver: the OIDC spec wording is ambiguous about RP-side verification
// and the most common real-world claim source — Microsoft Graph — does not
// even return JWTs. The trust model is therefore: TLS to the endpoint plus
// the configured EndpointAllowlist.
type distributedClaimsResolver struct {
	endpointAllowlist []string
	httpClient        *http.Client
	logger            *zap.Logger
}

// NewDistributedClaimsResolver validates the config and constructs a
// resolver. Returns (nil, nil) when cfg is nil or has Enabled=false so the
// caller does not need to special-case the disabled path.
func NewDistributedClaimsResolver(cfg *DistributedClaimsResolverConfig) (*distributedClaimsResolver, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	allowlist := make([]string, 0, len(cfg.EndpointAllowlist))
	for _, host := range cfg.EndpointAllowlist {
		host = strings.TrimSpace(strings.ToLower(host))
		if host == "" {
			continue
		}
		allowlist = append(allowlist, host)
	}

	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &distributedClaimsResolver{
		endpointAllowlist: allowlist,
		httpClient:        httpClient,
		logger:            logger,
	}, nil
}

// Resolve dereferences any distributed claims described by claims["_claim_names"]
// and claims["_claim_sources"], merging the resolved values back into the map
// under their original claim names. Failures for individual sources are
// logged and skipped — the surrounding authorization logic still runs against
// whatever did resolve, and missing claims will simply not match the
// configured allowed-attribute filters.
//
// The fallbackToken is used as the Bearer credential against any source that
// does not embed its own access_token. It can be nil when no fallback is
// available.
func (r *distributedClaimsResolver) Resolve(
	ctx context.Context,
	claims map[string]any,
	fallbackToken *oauth2.Token,
) {
	if claims == nil {
		return
	}
	names, ok := claims["_claim_names"].(map[string]any)
	if !ok || len(names) == 0 {
		return
	}
	sources, _ := claims["_claim_sources"].(map[string]any)

	for claimName, srcRefAny := range names {
		srcRef, ok := srcRefAny.(string)
		if !ok || srcRef == "" {
			r.logger.Warn("distributed claim source reference is not a string",
				zap.String("claim", claimName))
			continue
		}
		srcAny, ok := sources[srcRef]
		if !ok {
			r.logger.Warn("distributed claim source not found",
				zap.String("claim", claimName),
				zap.String("source", srcRef))
			continue
		}
		src, ok := srcAny.(map[string]any)
		if !ok {
			r.logger.Warn("distributed claim source is not an object",
				zap.String("claim", claimName),
				zap.String("source", srcRef))
			continue
		}
		// Aggregated claims (containing a "JWT" key) are not distributed —
		// they're inlined and just need to be parsed locally. We don't
		// implement aggregated-claim handling here; skip them so the rest
		// of the resolution still runs.
		if _, hasJWT := src["JWT"]; hasJWT {
			continue
		}

		endpoint, _ := src["endpoint"].(string)
		if endpoint == "" {
			r.logger.Warn("distributed claim source has no endpoint",
				zap.String("claim", claimName),
				zap.String("source", srcRef))
			continue
		}
		if !r.endpointAllowed(endpoint) {
			r.logger.Warn("distributed claim endpoint not in allowlist",
				zap.String("claim", claimName),
				zap.String("endpoint", endpoint))
			continue
		}

		bearer, _ := src["access_token"].(string)
		if bearer == "" && fallbackToken != nil {
			bearer = fallbackToken.AccessToken
		}

		value, err := r.fetchClaim(ctx, endpoint, bearer, claimName)
		if err != nil {
			r.logger.Error("failed to resolve distributed claim",
				zap.String("claim", claimName),
				zap.String("endpoint", endpoint),
				zap.Error(err))
			continue
		}
		claims[claimName] = value
		delete(names, claimName)
		if sources != nil {
			delete(sources, srcRef)
		}
	}

	if len(names) == 0 {
		delete(claims, "_claim_names")
	}
	if len(sources) == 0 {
		delete(claims, "_claim_sources")
	}
}

// endpointAllowed returns true if endpoint is an absolute http(s) URL whose
// host matches the configured allowlist (or any host when the allowlist is
// empty).
func (r *distributedClaimsResolver) endpointAllowed(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if len(r.endpointAllowlist) == 0 {
		return true
	}
	host := strings.ToLower(u.Hostname())
	for _, allowed := range r.endpointAllowlist {
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			return true
		}
	}
	return false
}

// fetchClaim issues a GET against endpoint, reads the body subject to a size
// cap, and decodes the response as either a JWT (per spec) or a JSON object
// (Microsoft Graph). It then locates the value associated with claimName
// inside the decoded payload.
func (r *distributedClaimsResolver) fetchClaim(
	ctx context.Context,
	endpoint, bearer, claimName string,
) (any, error) {
	httpCtx, cancel := context.WithTimeout(ctx, distributedClaimHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(httpCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Accept", "application/jwt, application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDistributedClaimBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if len(body) > maxDistributedClaimBodyBytes {
		return nil, fmt.Errorf("response body exceeds %d-byte cap", maxDistributedClaimBodyBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	payload, err := decodeClaimPayload(body)
	if err != nil {
		return nil, err
	}
	return extractClaimValue(payload, claimName), nil
}

// decodeClaimPayload accepts either a JWT (three dot-separated base64url
// segments) or a JSON object and returns the decoded payload as a map. The
// JWT signature is not verified — see the package-level note on the trust
// model.
func decodeClaimPayload(body []byte) (map[string]any, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, fmt.Errorf("empty response body")
	}
	// Heuristic: if the body looks like a JSON object, decode it directly.
	// Otherwise, try to parse it as a JWT.
	if trimmed[0] == '{' {
		var obj map[string]any
		if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
			return nil, fmt.Errorf("decode json: %w", err)
		}
		return obj, nil
	}
	parts := strings.Split(trimmed, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("response is neither a JSON object nor a JWT")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode jwt payload: %w", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(payloadBytes, &obj); err != nil {
		return nil, fmt.Errorf("decode jwt payload json: %w", err)
	}
	return obj, nil
}

// extractClaimValue picks the value for claimName out of a resolved payload.
// It checks (in order): a top-level key matching the claim name; a top-level
// "value" array (the shape Microsoft Graph returns from
// /v1.0/me/getMemberObjects and /v1.0/me/memberOf); and finally falls back to
// the entire payload, which is the spec-blessed shape (the response IS the
// claim set).
func extractClaimValue(payload map[string]any, claimName string) any {
	if v, ok := payload[claimName]; ok {
		return v
	}
	if v, ok := payload["value"]; ok {
		return v
	}
	return payload
}
