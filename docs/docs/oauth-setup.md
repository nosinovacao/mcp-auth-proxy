---
sidebar_position: 4
---

# OAuth Provider Setup

Configure OAuth providers to enable secure authentication for your MCP server.

## Google OAuth Setup

### 1. Google Cloud Console Configuration

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API:
   - Go to "APIs & Services" → "Library"
   - Search for "Google+ API" and enable it
4. Create OAuth consent screen:
   - Go to "APIs & Services" → "OAuth consent screen"
   - Choose "External" user type
   - Fill in required information

### 2. Create OAuth Credentials

1. Go to "APIs & Services" → "Credentials"
2. Click "Create credentials" → "OAuth client ID"
3. Choose "Web application"
4. Add authorized redirect URI: `{EXTERNAL_URL}/.auth/google/callback`
5. Note the Client ID and Client Secret

### 3. Configure MCP Auth Proxy

#### Allow specific users:

```bash
./mcp-auth-proxy \
  --external-url https://{your-domain} \
  --tls-accept-tos \
  --google-client-id "your-google-client-id" \
  --google-client-secret "your-google-client-secret" \
  --google-allowed-users "user1@example.com,user2@example.com" \
  -- your-mcp-command
```

#### Allow entire Google Workspaces:

```bash
./mcp-auth-proxy \
  --external-url https://{your-domain} \
  --tls-accept-tos \
  --google-client-id "your-google-client-id" \
  --google-client-secret "your-google-client-secret" \
  --google-allowed-workspaces "workspace1.com,workspace2.com" \
  -- your-mcp-command
```

## GitHub OAuth Setup

### 1. Register OAuth App

1. Go to [GitHub Developer Settings](https://github.com/settings/applications/new)
2. Fill in application details:
   - **Application name**: Your app name
   - **Homepage URL**: `https://{your-domain}`
   - **Authorization callback URL**: `{EXTERNAL_URL}/.auth/github/callback`
3. Note the Client ID and generate a Client Secret

### 2. Configure MCP Auth Proxy

```bash
./mcp-auth-proxy \
  --external-url https://{your-domain} \
  --tls-accept-tos \
  --github-client-id "your-github-client-id" \
  --github-client-secret "your-github-client-secret" \
  --github-allowed-users "username1,username2" \
  --github-allowed-orgs "org1,org2:team1" \
  -- your-mcp-command
```

## Generic OIDC Provider Setup

### Supported Providers

- Okta
- Auth0
- Azure AD (Microsoft Entra ID)
- Keycloak
- Any OpenID Connect compatible provider

### 1. Provider Configuration

1. Create a new application/client in your OIDC provider
2. Set redirect URI: `{EXTERNAL_URL}/.auth/oidc/callback`
3. Note the:
   - Configuration URL (usually `{issuer}/.well-known/openid-configuration`)
   - Client ID
   - Client Secret

### 2. Configure MCP Auth Proxy

#### Exact user matching:

```bash
./mcp-auth-proxy \
  --external-url https://{your-domain} \
  --tls-accept-tos \
  --oidc-configuration-url "https://your-provider.com/.well-known/openid-configuration" \
  --oidc-client-id "your-oidc-client-id" \
  --oidc-client-secret "your-oidc-client-secret" \
  --oidc-allowed-users "user1@example.com,user2@example.com" \
  -- your-mcp-command
```

#### Glob pattern matching:

```bash
./mcp-auth-proxy \
  --external-url https://{your-domain} \
  --tls-accept-tos \
  --oidc-configuration-url "https://your-provider.com/.well-known/openid-configuration" \
  --oidc-client-id "your-oidc-client-id" \
  --oidc-client-secret "your-oidc-client-secret" \
  --oidc-allowed-users-glob "*@example.com" \
  -- your-mcp-command
```

#### Attribute-based authorization:

Authorize users based on attributes like group memberships or roles from the userinfo endpoint:

```bash
./mcp-auth-proxy \
  --external-url https://{your-domain} \
  --tls-accept-tos \
  --oidc-configuration-url "https://your-provider.com/.well-known/openid-configuration" \
  --oidc-client-id "your-oidc-client-id" \
  --oidc-client-secret "your-oidc-client-secret" \
  --oidc-scopes "openid,profile,email,groups" \
  --oidc-allowed-attributes "/groups=engineering" \
  -- your-mcp-command
```

#### Attribute glob patterns:

```bash
./mcp-auth-proxy \
  --external-url https://{your-domain} \
  --tls-accept-tos \
  --oidc-configuration-url "https://your-provider.com/.well-known/openid-configuration" \
  --oidc-client-id "your-oidc-client-id" \
  --oidc-client-secret "your-oidc-client-secret" \
  --oidc-scopes "openid,profile,email,groups" \
  --oidc-allowed-attributes-glob "/groups=*-admins" \
  -- your-mcp-command
```

### Provider-Specific Examples

#### Okta

```bash
--oidc-configuration-url "https://your-domain.okta.com/.well-known/openid-configuration"
```

For group-based authorization with Okta:

1. Add the `groups` scope to your request:

   ```bash
   --oidc-scopes "openid,profile,email,groups"
   ```

2. Configure a groups claim in Okta Admin:
   - Go to Security → API → Authorization Servers
   - Select your authorization server → Claims tab
   - Add a claim named "groups" with value type "Groups" and filter as needed

3. Use attribute-based authorization:
   ```bash
   --oidc-allowed-attributes "/groups=data-science"
   # or with glob patterns:
   --oidc-allowed-attributes-glob "/groups=*-admins"
   ```

#### Auth0

```bash
--oidc-configuration-url "https://your-domain.auth0.com/.well-known/openid-configuration"
```

#### Azure AD / Microsoft Entra ID

```bash
--oidc-configuration-url "https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid-configuration"
```

##### Group Membership via OIDC Distributed Claims

When a user belongs to more than ~200 groups, Entra ID does not embed the
group list in the ID token or userinfo response. Instead, it emits a
[distributed claim](https://openid.net/specs/openid-connect-core-1_0.html#AggregatedDistributedClaims)
pointing at a Microsoft Graph endpoint that holds the actual values. The
proxy can dereference that endpoint with the signed-in user's access token
and merge the resolved values back into the user's claim set, so the
existing `--oidc-allowed-attributes /groups=...` filter matches as it would
for any other IdP. This requires only the delegated `User.Read` permission
the user already consents to at sign-in — no `GroupMember.Read.All` /
`Directory.Read.All` application permission and no admin consent.

1. **Collect the group object IDs** you want to allow (Entra ID → Groups →
   copy each group's Object ID — these are GUIDs).

2. **Run the proxy** with distributed-claims resolution enabled and the
   relevant Graph hosts allowlisted:

   ```bash
   ./mcp-auth-proxy \
     --external-url https://{your-domain} \
     --tls-accept-tos \
     --oidc-configuration-url "https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid-configuration" \
     --oidc-client-id "$CLIENT_ID" \
     --oidc-client-secret "$CLIENT_SECRET" \
     --oidc-resolve-distributed-claims \
     --oidc-distributed-claims-endpoint-allowlist "graph.microsoft.com,graph.windows.net" \
     --oidc-allowed-attributes "/groups=group-id-1,/groups=group-id-2" \
     -- your-mcp-command
   ```

   For sovereign clouds (e.g., US Government), allowlist the corresponding
   Graph host instead — for example `graph.microsoft.us`.

Notes:

- `--oidc-resolve-distributed-claims` is opt-in and off by default. When it
  is disabled, distributed claims are left as opaque references and any
  attribute filter targeting them will not match.
- The endpoint allowlist has no default value; you must enumerate the
  Graph hosts your tenant emits. Both `graph.microsoft.com` (current app
  registrations) and `graph.windows.net` (legacy) appear in real-world
  Entra tokens.
- The same `--oidc-client-id`/`--oidc-client-secret` are reused — no
  separate credentials are needed.
- JWT signatures on resolved-claim responses are not verified. Trust is
  based on TLS to the endpoint plus the host allowlist.
- If the distributed-claims endpoint is unreachable, the affected claim is
  simply absent and any filter that depended on it will not match (fail
  closed). Users already authorized by another filter are unaffected.

See the [Configuration Reference](./configuration.md#oidc-distributed-claims)
for the full flag reference.

## Multiple Providers

You can enable multiple OAuth providers simultaneously:

```bash
./mcp-auth-proxy \
  --external-url https://{your-domain} \
  --tls-accept-tos \
  --password fallback-password \
  --google-client-id "google-client-id" \
  --google-client-secret "google-client-secret" \
  --google-allowed-users "user@gmail.com" \
  --github-client-id "github-client-id" \
  --github-client-secret "github-client-secret" \
  --github-allowed-users "githubuser" \
  -- your-mcp-command
```

## Environment Variables

All OAuth settings can be configured using environment variables:

```bash
export GOOGLE_CLIENT_ID="your-google-client-id"
export GOOGLE_CLIENT_SECRET="your-google-client-secret"
export GOOGLE_ALLOWED_USERS="user1@example.com,user2@example.com"
export GOOGLE_ALLOWED_WORKSPACES="workspace1.com,workspace2.com"

export GITHUB_CLIENT_ID="your-github-client-id"
export GITHUB_CLIENT_SECRET="your-github-client-secret"
export GITHUB_ALLOWED_USERS="username1,username2"
export GITHUB_ALLOWED_ORGS="org1,org2:team1"

export OIDC_CONFIGURATION_URL="https://provider.com/.well-known/openid-configuration"
export OIDC_CLIENT_ID="your-oidc-client-id"
export OIDC_CLIENT_SECRET="your-oidc-client-secret"
export OIDC_SCOPES="openid,profile,email,groups"
export OIDC_ALLOWED_USERS="user1@example.com,user2@example.com"
export OIDC_ALLOWED_USERS_GLOB="*@example.com"
export OIDC_ALLOWED_ATTRIBUTES="/groups=admin,/department=engineering"
export OIDC_ALLOWED_ATTRIBUTES_GLOB="/groups=*-admins"

# OIDC distributed-claims resolution (e.g., for Entra ID group overage).
# Match resolved groups via OIDC_ALLOWED_ATTRIBUTES above (e.g., /groups=group-id).
export OIDC_RESOLVE_DISTRIBUTED_CLAIMS="true"
export OIDC_DISTRIBUTED_CLAIMS_ENDPOINT_ALLOWLIST="graph.microsoft.com,graph.windows.net"

./mcp-auth-proxy --external-url https://{your-domain} --tls-accept-tos -- your-mcp-command
```
