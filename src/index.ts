export default {
    async fetch(request: Request, env: Env): Promise<Response> {
        const url = new URL(request.url);

        // CORS preflight
        if (request.method === 'OPTIONS') {
            return handleCORS(env.FRONTEND_URL);
        }

        // Route handler
        if (url.pathname === '/auth/github' && request.method === 'GET') {
            return handleGitHubAuth(env);
        }

        if (url.pathname === '/auth/github/callback' && request.method === 'GET') {
            return handleGitHubCallback(request, env);
        }

        if (url.pathname === '/auth/me' && request.method === 'GET') {
            return handleAuthMe(request, env);
        }

        if (url.pathname === '/auth/logout' && request.method === 'POST') {
            return handleLogout(env.FRONTEND_URL);
        }

        return new Response('Not Found', { status: 404 });
    }
};

interface Env {
    GITHUB_CLIENT_ID: string;
    GITHUB_CLIENT_SECRET: string;
    AUTH_SECRET: string;
    FRONTEND_URL: string;
}

interface UserPayload {
    github_id: number;
    username: string;
    avatar_url: string;
    iat: number;
    exp: number;
}

// CORS helper
function handleCORS(frontendUrl: string): Response {
    return new Response(null, {
        status: 204,
        headers: {
            'Access-Control-Allow-Origin': frontendUrl,
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            'Access-Control-Max-Age': '86400',
        }
    });
}

function addCORSHeaders(response: Response, frontendUrl: string): Response {
    const newHeaders = new Headers(response.headers);
    newHeaders.set('Access-Control-Allow-Origin', frontendUrl);
    return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: newHeaders
    });
}

// Generate random state
async function generateState(): Promise<string> {
    const buffer = new Uint8Array(32);
    crypto.getRandomValues(buffer);
    return Array.from(buffer).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Sign data using HMAC-SHA256
async function sign(data: string, secret: string): Promise<string> {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
    return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

// Verify HMAC signature (constant-time)
async function verify(data: string, signature: string, secret: string): Promise<boolean> {
    const expectedSig = await sign(data, secret);
    if (expectedSig.length !== signature.length) return false;

    // Constant-time comparison
    let result = 0;
    for (let i = 0; i < expectedSig.length; i++) {
        result |= expectedSig.charCodeAt(i) ^ signature.charCodeAt(i);
    }
    return result === 0;
}

// Create JWT
async function createJWT(payload: UserPayload, secret: string): Promise<string> {
    const header = { alg: 'HS256', typ: 'JWT' };
    const encodedHeader = btoa(JSON.stringify(header));
    const encodedPayload = btoa(JSON.stringify(payload));
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const signature = await sign(signingInput, secret);
    return `${signingInput}.${signature}`;
}

// Verify JWT
async function verifyJWT(token: string, secret: string): Promise<UserPayload | null> {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [encodedHeader, encodedPayload, signature] = parts;
    const signingInput = `${encodedHeader}.${encodedPayload}`;

    // Verify signature
    const isValid = await verify(signingInput, signature, secret);
    if (!isValid) return null;

    // Decode and validate payload
    try {
        const payload: UserPayload = JSON.parse(atob(encodedPayload));

        // Check expiration
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp < now) return null;

        return payload;
    } catch {
        return null;
    }
}

// GET /auth/github
async function handleGitHubAuth(env: Env): Promise<Response> {
    const state = await generateState();
    const stateExpiry = Math.floor(Date.now() / 1000) + 300; // 5 minutes
    const stateData = `${state}:${stateExpiry}`;
    const signature = await sign(stateData, env.AUTH_SECRET);

    const githubAuthUrl = new URL('https://github.com/login/oauth/authorize');
    githubAuthUrl.searchParams.set('client_id', env.GITHUB_CLIENT_ID);
    githubAuthUrl.searchParams.set('redirect_uri', `${new URL(env.FRONTEND_URL).origin}/auth/github/callback`);
    githubAuthUrl.searchParams.set('scope', 'read:user');
    githubAuthUrl.searchParams.set('state', state);

    return new Response(null, {
        status: 302,
        headers: {
            'Location': githubAuthUrl.toString(),
            'Set-Cookie': `oauth_state=${stateData}:${signature}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300`
        }
    });
}

// GET /auth/github/callback
async function handleGitHubCallback(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');

    if (!code || !state) {
        return new Response('Missing code or state', { status: 400 });
    }

    // Verify state
    const cookies = request.headers.get('Cookie') || '';
    const stateCookie = cookies.split(';').find(c => c.trim().startsWith('oauth_state='));
    if (!stateCookie) {
        return new Response('Missing state cookie', { status: 400 });
    }

    const cookieValue = stateCookie.split('=')[1];
    const [cookieState, cookieExpiry, cookieSignature] = cookieValue.split(':');

    // Verify signature
    const stateData = `${cookieState}:${cookieExpiry}`;
    const isValid = await verify(stateData, cookieSignature, env.AUTH_SECRET);
    if (!isValid || cookieState !== state) {
        return new Response('Invalid state', { status: 400 });
    }

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (parseInt(cookieExpiry) < now) {
        return new Response('State expired', { status: 400 });
    }

    // Exchange code for access token
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            client_id: env.GITHUB_CLIENT_ID,
            client_secret: env.GITHUB_CLIENT_SECRET,
            code,
        })
    });

    const tokenData = await tokenResponse.json() as { access_token?: string; error?: string };
    if (!tokenData.access_token) {
        return new Response('Failed to get access token', { status: 500 });
    }

    // Fetch user profile
    const userResponse = await fetch('https://api.github.com/user', {
        headers: {
            'Authorization': `Bearer ${tokenData.access_token}`,
            'Accept': 'application/json',
            'User-Agent': 'OpenQuests-Auth'
        }
    });

    const userData = await userResponse.json() as { id: number; login: string; avatar_url: string };

    // Create session token
    const now_ts = Math.floor(Date.now() / 1000);
    const payload: UserPayload = {
        github_id: userData.id,
        username: userData.login,
        avatar_url: userData.avatar_url,
        iat: now_ts,
        exp: now_ts + 86400, // 24 hours
    };

    const sessionToken = await createJWT(payload, env.AUTH_SECRET);

    // Redirect to frontend with token
    const redirectUrl = new URL(env.FRONTEND_URL);
    redirectUrl.searchParams.set('token', sessionToken);

    return new Response(null, {
        status: 302,
        headers: {
            'Location': redirectUrl.toString(),
            'Set-Cookie': 'oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0' // Clear state cookie
        }
    });
}

// GET /auth/me
async function handleAuthMe(request: Request, env: Env): Promise<Response> {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return addCORSHeaders(
            new Response(JSON.stringify({ error: 'Unauthorized' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json' }
            }),
            env.FRONTEND_URL
        );
    }

    const token = authHeader.substring(7);
    const payload = await verifyJWT(token, env.AUTH_SECRET);

    if (!payload) {
        return addCORSHeaders(
            new Response(JSON.stringify({ error: 'Invalid or expired token' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json' }
            }),
            env.FRONTEND_URL
        );
    }

    return addCORSHeaders(
        new Response(JSON.stringify({
            username: payload.username,
            avatarUrl: payload.avatar_url,
            id: payload.github_id
        }), {
            headers: { 'Content-Type': 'application/json' }
        }),
        env.FRONTEND_URL
    );
}

// POST /auth/logout
function handleLogout(frontendUrl: string): Response {
    return addCORSHeaders(
        new Response(JSON.stringify({ message: 'Logged out' }), {
            headers: { 'Content-Type': 'application/json' }
        }),
        frontendUrl
    );
}
