# MCP Auth Proxy

![Secure your MCP server with OAuth 2.1 — in a minute](./mcp-auth-proxy.svg)

> If you found value here, please consider starring.

## Overview

- **Drop-in OAuth 2.1/OIDC gateway for MCP servers — put it in front, no code changes.**
- **Your IdP, your choice**: Google, GitHub, or any OIDC provider — e.g. Okta, Auth0, Azure AD, Keycloak — plus optional password.
- **Flexible user matching**: Support exact matching and glob patterns for user authorization (e.g., `*@company.com`)
- **Publish local MCP servers safely**: Supports all stdio, SSE, and HTTP transports. For stdio, traffic is converted to `/mcp`. For SSE/HTTP, it's proxied as-is. Of course, with authentication.
- **Verified across major MCP clients**: Claude, Claude Code, ChatGPT, GitHub Copilot, Cursor, etc. — the proxy smooths client-specific quirks for consistent auth.

---

📖 **For detailed usage, configuration, and examples, see the [Documentation](https://sigbit.github.io/mcp-auth-proxy/)**

## Quickstart

> Domain binding & 80/443 must be accessible from outside.

Download binary from [release](https://github.com/sigbit/mcp-auth-proxy/releases) page.

If you use stdio transport

```sh
./mcp-auth-proxy \
  --external-url https://{your-domain} \
  --tls-accept-tos \
  --password changeme \
  -- npx -y @modelcontextprotocol/server-filesystem ./
```

That's it! Your HTTP endpoint is now available at `https://{your-domain}/mcp`.

- stdio (when a command is specified): MCP endpoint is https://{your-domain}/mcp.
- SSE/HTTP (when a URL is specified): MCP endpoint uses the backend’s original path (no conversion).

> Already have certificates? Pass `--tls-cert-file` and `--tls-key-file` instead of `--tls-accept-tos`.

## Why not MCP Gateway?

mcp-auth-proxy: **A lightweight proxy that adds authentication to any MCP server** (optional stdio→HTTP(S) conversion)  
MCP Gateway: **A hub to orchestrate multiple MCP servers** (aggregation, catalog integration)

### When to choose `mcp-auth-proxy`

- **You just need to add auth to one or a few MCPs** (enforce OAuth/OIDC/password-only)
- **Catalog integration and aggregation aren’t needed** (e.g., self-hosted or independently managed MCP deployments)

### When to choose MCP Gateway

- **You need to manage multiple MCPs centrally** (aggregation, policies/permissions, auditing, centralized logging)
- **You want catalog integration and aggregation**

_Note_: They are not mutually exclusive. You can **put `mcp-auth-proxy` in front of a Gateway's public endpoint to enforce authentication** if the Gateway itself doesn't handle it.

**TL;DR:** Orchestrate many → Gateway / Expose safely & quickly → mcp-auth-proxy

## OIDC Distributed Claims (group / role overage)

Some IdPs cannot embed every claim value directly inside the ID token or
userinfo response — most commonly when a user belongs to too many groups
or roles for them to fit. Instead, the IdP advertises a *reference* to a
separate endpoint that returns the actual values. This is the **OIDC
distributed-claims** mechanism specified in
[OIDC Core 1.0 §5.6.2](https://openid.net/specs/openid-connect-core-1_0.html#AggregatedDistributedClaims):

```json
{
  "_claim_names":   { "groups": "src1" },
  "_claim_sources": { "src1": { "endpoint": "https://...", "access_token": "..." } }
}
```

When `--oidc-resolve-distributed-claims` is enabled, mcp-auth-proxy
dereferences each `_claim_sources` endpoint, merges the resolved values
back into the user's claim set, and then evaluates the existing
`--oidc-allowed-attributes` / `--oidc-allowed-attributes-glob` filters
against the enriched claims — so the same flag you'd use for inline group
claims also works for overage cases. The proxy uses the `access_token`
from `_claim_sources` when present and otherwise falls back to the user's
delegated access token. Responses can be either JWTs (per spec) or plain
JSON objects (the form Microsoft Graph returns).

This feature is **opt-in** and **off by default**.

**Trust model.** The resolved-claim response signature is **not** verified.
The OIDC spec is ambiguous about RP-side verification and the most common
real-world claim source (Microsoft Graph) returns plain JSON rather than
JWTs, so verification would not be applicable there. Trust is therefore
based on the TLS connection to the endpoint plus the host allowlist below.

**Endpoint allowlist.** Because `_claim_sources.endpoint` comes from the
token itself, a misconfigured or compromised IdP could in principle point
the proxy at an attacker-controlled URL. Set
`--oidc-distributed-claims-endpoint-allowlist` to the specific host
suffixes the proxy is allowed to fetch from. Each entry matches the URL
host exactly or as a parent domain (e.g., `graph.microsoft.com` matches
`graph.microsoft.com` and `us.graph.microsoft.com`, but not `evil.com`).
The allowlist has no default value and the proxy will not pre-populate it
for any provider — you must enumerate the hosts your IdP advertises.

### Example: Microsoft Entra ID group overage

Entra ID emits distributed claims when a user belongs to more than ~200
groups (the *group overage* condition). The `_claim_sources.endpoint`
advertised by Entra typically points at `graph.microsoft.com` for current
app registrations, or at the legacy `graph.windows.net` host for older
ones — both should be allowlisted if you want to support both.

The Entra app registration only needs the delegated `User.Read` permission
the user already consents to at sign-in. No `GroupMember.Read.All` /
`Directory.Read.All` application permission and no admin consent is
required, because the proxy reuses the user's own access token to call the
endpoint Entra advertised.

```sh
mcp-auth-proxy \
  --oidc-configuration-url "https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration" \
  --oidc-client-id "$CLIENT_ID" \
  --oidc-client-secret "$CLIENT_SECRET" \
  --oidc-resolve-distributed-claims \
  --oidc-distributed-claims-endpoint-allowlist "graph.microsoft.com,graph.windows.net" \
  --oidc-allowed-attributes "/groups=group-id-1,/groups=group-id-2" \
  --external-url "https://mcp.example.com" \
  http://localhost:8000
```

For sovereign clouds, allowlist the corresponding Graph host instead
(e.g., `graph.microsoft.us`).

**Authorization semantics.** Distributed-claims resolution feeds into the
existing attribute filters; it does not introduce a new allow path of its
own. `--oidc-allowed-users`, `--oidc-allowed-users-glob`,
`--oidc-allowed-attributes`, and `--oidc-allowed-attributes-glob` are
combined via OR — a user is allowed if they match any one of them. If the
distributed-claims endpoint is unreachable, the affected claim is simply
absent from the user's claim set, so any filter that depended on it will
not match (fail closed). Users already authorized by another filter are
not affected by a claim-source outage.

The same mechanism works with any other OIDC provider that emits
distributed claims (Keycloak with a custom claim mapper, etc.) — set the
allowlist to the provider's claim-source host and configure the existing
`--oidc-allowed-attributes` filters as usual.

## Verified MCP Client

| MCP Client        | Status | Notes                                            |
| ----------------- | ------ | ------------------------------------------------ |
| Claude - Web      | ✅     |                                                  |
| Claude - Desktop  | ✅     |                                                  |
| Claude Code       | ✅     |                                                  |
| ChatGPT - Web     | ✅     | Need to implement `search` and `fetch` tools.(1) |
| ChatGPT - Desktop | ✅     | Need to implement `search` and `fetch` tools.(1) |
| GitHub Copilot    | ✅     |                                                  |
| Cursor            | ✅     |                                                  |

- \*1: https://platform.openai.com/docs/mcp
