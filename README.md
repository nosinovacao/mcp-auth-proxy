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

## Microsoft Entra ID Group-Based Access Control (Microsoft Graph API)

For Microsoft Entra ID (formerly Azure AD) deployments that require
group-based access control, use `--entraid-allowed-groups` to specify which
Entra ID group object IDs are allowed to access the MCP server. This flag
augments the OIDC provider, so the `--oidc-configuration-url`,
`--oidc-client-id`, and `--oidc-client-secret` flags must already be
configured against the Entra tenant.

This feature calls the Microsoft Graph `getMemberObjects` endpoint with the
signed-in user's delegated access token, matching the approach used by Grafana
(`force_use_graph_api: true`). It is useful when group claims are not present
in the ID token or userinfo response (common in Entra ID).

**Prerequisites:**
- The Entra ID app registration only needs the delegated `User.Read` permission
  the user already consents to at sign-in. No `GroupMember.Read.All` /
  `Directory.Read.All` application permission and no admin consent is required.
- The same `--oidc-client-id` and `--oidc-client-secret` are reused.

**Example:**

```sh
mcp-auth-proxy \
  --oidc-configuration-url "https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration" \
  --oidc-client-id "$CLIENT_ID" \
  --oidc-client-secret "$CLIENT_SECRET" \
  --entraid-allowed-groups "group-id-1,group-id-2" \
  --external-url "https://mcp.example.com" \
  http://localhost:8000
```

For sovereign clouds, override the Graph API endpoint:

```sh
--entraid-graph-api-endpoint "https://graph.microsoft.us"
```

**Authorization semantics:** `--entraid-allowed-groups` adds group
membership as an additional allow path. It is combined with
`--oidc-allowed-users`, `--oidc-allowed-users-glob`,
`--oidc-allowed-attributes`, and `--oidc-allowed-attributes-glob` via OR — a
user is allowed if they match any one of those filters. If the Graph lookup
is reached (i.e., none of the earlier filters already allowed the user) and
Graph API is unreachable or returns an error, that check denies access (fail
closed). Users already authorized by the earlier filters are not affected by
a Graph outage.

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
