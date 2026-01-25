# OpenQuests GitHub Auth Service

A minimal, stateless GitHub OAuth service built with Cloudflare Workers that authenticates users and returns their GitHub identity.

## Features

- ✅ GitHub OAuth (Authorization Code Flow)
- ✅ Stateless JWT session tokens (24-hour TTL)
- ✅ CSRF protection via OAuth state parameter
- ✅ CORS-enabled for static frontends
- ✅ No database or KV storage required
- ✅ ~300 LOC, no external dependencies

## Setup

### 1. Create GitHub OAuth App

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill in:
   - **Application name**: OpenQuests Auth
   - **Homepage URL**: Your frontend URL (e.g., `https://username.github.io/openquests`)
   - **Authorization callback URL**: `https://your-worker.workers.dev/auth/github/callback`
4. Click "Register application"
5. Note your **Client ID** and generate a **Client Secret**

### 2. Configure Environment Variables

Generate a secure random secret for signing tokens:

```bash
# Generate AUTH_SECRET (32+ bytes, hex-encoded)
openssl rand -hex 32
```

Set secrets using Wrangler:

```bash
cd services/auth

# Set GitHub OAuth credentials
wrangler secret put GITHUB_CLIENT_ID
wrangler secret put GITHUB_CLIENT_SECRET

# Set auth signing secret
wrangler secret put AUTH_SECRET

# Set your frontend URL
wrangler secret put FRONTEND_URL
```

### 3. Install Dependencies

```bash
npm install
```

### 4. Development

```bash
npm run dev
```

This starts a local development server at `http://localhost:8787`.

### 5. Deploy

```bash
npm run deploy
```

Your worker will be deployed to `https://openquests-auth.<your-subdomain>.workers.dev`.

## API Reference

### `GET /auth/github`

Initiates GitHub OAuth flow.

**Response**: Redirects to GitHub authorization page

---

### `GET /auth/github/callback`

OAuth callback endpoint (called by GitHub after user authorization).

**Query Parameters**:
- `code`: OAuth authorization code
- `state`: CSRF protection token

**Response**: Redirects to frontend with session token
```
https://your-frontend.com?token=<jwt>
```

---

### `GET /auth/me`

Authenticates and returns user information.

**Headers**:
```
Authorization: Bearer <token>
```

**Response** (200 OK):
```json
{
  "username": "octocat",
  "avatarUrl": "https://avatars.githubusercontent.com/u/583231",
  "id": 583231
}
```

**Error** (401 Unauthorized):
```json
{
  "error": "Invalid or expired token"
}
```

---

### `POST /auth/logout`

Stateless logout endpoint (client should delete stored token).

**Response** (200 OK):
```json
{
  "message": "Logged out"
}
```

## Frontend Integration

### 1. Login Flow

Redirect users to the worker's OAuth endpoint:

```javascript
function login() {
  window.location.href = 'https://your-worker.workers.dev/auth/github';
}
```

### 2. Handle OAuth Callback

After successful authentication, the worker redirects back to your frontend with a token:

```javascript
// Extract token from URL
const urlParams = new URLSearchParams(window.location.search);
const token = urlParams.get('token');

if (token) {
  // Store token
  localStorage.setItem('auth_token', token);
  
  // Clean URL
  window.history.replaceState({}, document.title, window.location.pathname);
}
```

### 3. Authenticated Requests

Include the token in API requests:

```javascript
const token = localStorage.getItem('auth_token');

const response = await fetch('https://your-worker.workers.dev/auth/me', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});

const user = await response.json();
console.log(user); // { username: "octocat", avatarUrl: "...", id: 583231 }
```

### 4. Logout

```javascript
function logout() {
  // Delete local token
  localStorage.removeItem('auth_token');
  
  // Optionally notify the server
  await fetch('https://your-worker.workers.dev/auth/logout', {
    method: 'POST'
  });
}
```

## Security

- **CSRF Protection**: OAuth state parameter is signed and verified
- **Token Signing**: JWTs use HMAC-SHA256 with constant-time verification
- **CORS**: Restricted to configured frontend domain only
- **Stateless**: No session storage, all state in signed tokens
- **Short-lived**: Tokens expire after 24 hours

## Token Structure

Tokens are JWTs (HS256) containing:

```json
{
  "github_id": 583231,
  "username": "octocat",
  "avatar_url": "https://avatars.githubusercontent.com/u/583231",
  "iat": 1234567890,
  "exp": 1234654290
}
```

## Troubleshooting

### "Invalid state" error
- Ensure cookies are enabled
- Check that callback URL matches OAuth app configuration
- Verify AUTH_SECRET is set correctly

### "Unauthorized" when calling /auth/me
- Check token is being sent in Authorization header
- Verify token hasn't expired (24-hour TTL)
- Ensure AUTH_SECRET hasn't changed

### CORS errors
- Verify FRONTEND_URL matches your frontend's origin exactly
- Include protocol (`https://`) in FRONTEND_URL

## Development Notes

- Worker uses Web Crypto API for all cryptographic operations
- No external libraries (zero npm dependencies at runtime)
- Fully stateless - scales infinitely on Cloudflare's edge network
- Compatible with any static site host (GitHub Pages, Netlify, Vercel, etc.)
