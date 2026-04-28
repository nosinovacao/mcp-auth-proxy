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

##### Group Membership via Microsoft Graph API

Entra ID often does not emit group claims in the ID token or userinfo response,
so `--oidc-allowed-attributes` against `/groups` will not work out of the box.
Instead, use `--entraid-allowed-groups` to have the proxy resolve group
membership via the Microsoft Graph
[`checkMemberGroups`](https://learn.microsoft.com/en-us/graph/api/user-checkmembergroups)
endpoint, using the OIDC client credentials.

1. **Grant the `GroupMember.Read.All` application permission** on the Entra ID
   app registration:
   - In the Azure portal, open your app registration → **API permissions**.
   - Click **Add a permission** → **Microsoft Graph** → **Application
     permissions**.
   - Search for and add `GroupMember.Read.All`.
   - Click **Grant admin consent** for your tenant (admin role required).

2. **Collect the group object IDs** you want to allow (Entra ID → Groups → copy
   each group's Object ID — these are GUIDs).

3. **Run the proxy** with `--entraid-allowed-groups`:

   ```bash
   ./mcp-auth-proxy \
     --external-url https://{your-domain} \
     --tls-accept-tos \
     --oidc-configuration-url "https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid-configuration" \
     --oidc-client-id "$CLIENT_ID" \
     --oidc-client-secret "$CLIENT_SECRET" \
     --entraid-allowed-groups "group-id-1,group-id-2" \
     -- your-mcp-command
   ```

   For sovereign clouds (e.g., US Government), override the Graph endpoint:

   ```bash
   --entraid-graph-api-endpoint "https://graph.microsoft.us"
   ```

Notes:

- `--entraid-allowed-groups` is combined with `--oidc-allowed-users`,
  `--oidc-allowed-users-glob`, `--oidc-allowed-attributes`, and
  `--oidc-allowed-attributes-glob` via OR.
- The same `--oidc-client-id`/`--oidc-client-secret` are reused for the Graph
  API call — no separate credentials are needed.
- If the Graph lookup is reached and the Graph API is unreachable or returns an
  error, the check denies access (fail closed).

See the [Configuration Reference](./configuration.md#microsoft-entra-id-graph-api-group-membership)
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

# Microsoft Entra ID group membership (Graph API)
export ENTRAID_ALLOWED_GROUPS="group-id-1,group-id-2"
# Override only for sovereign clouds, otherwise omit:
# export ENTRAID_GRAPH_API_ENDPOINT="https://graph.microsoft.us"

./mcp-auth-proxy --external-url https://{your-domain} --tls-accept-tos -- your-mcp-command
```
