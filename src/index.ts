export default {
    async fetch(request: Request, env: Env): Promise<Response> {
        const url = new URL(request.url);

        // CORS preflight
        if (request.method === 'OPTIONS') {
            return handleCORS(env.FRONTEND_URL);
        }

        // Route handler
        if (url.pathname === '/auth/github' && request.method === 'GET') {
            return handleGitHubAuth(request, env);
        }

        if (url.pathname === '/auth/github/callback' && request.method === 'GET') {
            return handleGitHubCallback(request, env);
        }

        if (url.pathname === '/action' && request.method === 'POST') {
            return handleAction(request, env);
        }

        if (url.pathname === '/auth/me' && request.method === 'GET') {
            return handleAuthMe(request, env);
        }

        if (url.pathname === '/auth/logout' && request.method === 'POST') {
            return handleLogout(env.FRONTEND_URL);
        }

        if (url.pathname === '/api/create-character' && request.method === 'POST') {
            return handleCreateCharacter(request, env);
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
    access_token: string;
    iat: number;
    exp: number;
}

interface ActionBody {
    world: string;
    issueNumber: number;
    comment: string;
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

// Sign data using HMAC-SHA256 (returns base64url-encoded signature)
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
    // Use base64url encoding (URL-safe: replace +/= with -_)
    return btoa(String.fromCharCode(...new Uint8Array(signature)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
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
async function handleGitHubAuth(request: Request, env: Env): Promise<Response> {
    const state = await generateState();
    const stateExpiry = Math.floor(Date.now() / 1000) + 300; // 5 minutes
    const stateData = `${state}:${stateExpiry}`;
    const signature = await sign(stateData, env.AUTH_SECRET);

    const githubAuthUrl = new URL('https://github.com/login/oauth/authorize');
    githubAuthUrl.searchParams.set('client_id', env.GITHUB_CLIENT_ID);
    githubAuthUrl.searchParams.set('redirect_uri', `${new URL(request.url).origin}/auth/github/callback`);
    githubAuthUrl.searchParams.set('scope', 'read:user public_repo');
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
    // Split only on first two colons to preserve signature
    const parts = cookieValue.split(':');
    const cookieState = parts[0];
    const cookieExpiry = parts[1];
    const cookieSignature = parts.slice(2).join(':'); // Rejoin in case signature contains colons

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
        access_token: tokenData.access_token,
        iat: now_ts,
        exp: now_ts + 86400
    };

    const sessionToken = await createJWT(payload, env.AUTH_SECRET);

    // Redirect to frontend with token
    const redirectUrl = new URL(env.FRONTEND_URL + '/openquests/');
    redirectUrl.searchParams.set('token', sessionToken);

    return new Response(null, {
        status: 302,
        headers: {
            'Location': redirectUrl.toString(),
            'Set-Cookie': 'oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0' // Clear state cookie
        }
    });
}

async function extractPayload(request: Request, env: Env) {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return null;
    }
    const token = authHeader.substring(7);
    const payload = await verifyJWT(token, env.AUTH_SECRET);
    return payload;
}

function invalidTokenResponse(env: Env) {
    return addCORSHeaders(
        new Response(JSON.stringify({ error: 'Invalid or expired token' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' }
        }),
        env.FRONTEND_URL
    );
}


// GET /auth/me
async function handleAuthMe(request: Request, env: Env): Promise<Response> {
    const payload = await extractPayload(request, env);
    if (!payload) {
        return invalidTokenResponse(env);
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

// POST /action
async function handleAction(request: Request, env: Env): Promise<Response> {
    const body = await request.json() as ActionBody;
    const world = body.world;
    const issueNumber = body.issueNumber;
    const comment = body.comment;

    const payload = await extractPayload(request, env);
    if (!payload) {
        return invalidTokenResponse(env);
    }

    const accessToken = payload.access_token;

    const response = await fetch(`https://api.github.com/repos/the-real-han/${world}/issues/${issueNumber}/comments`, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Accept': 'application/vnd.github.v3+json',
            'Content-Type': 'application/json',
            'User-Agent': 'OpenQuests-Proxy'
        },
        body: JSON.stringify({ body: comment }),
    });

    if (!response.ok) {
        const error = await response.json().catch(() => ({ message: response.statusText }));
        return addCORSHeaders(
            new Response(JSON.stringify({ error }), {
                status: response.status,
                headers: { 'Content-Type': 'application/json' }
            }),
            env.FRONTEND_URL
        );
    }

    return addCORSHeaders(
        new Response(JSON.stringify({
            message: 'Comment added successfully',
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

interface CreateCharacterBody {
    world: string;
    characterName: string;
    characterClass: 'Warrior' | 'Lancer' | 'Archer' | 'Monk' | 'Adventurer';
    backstory?: string;
}

// POST /api/create-character
async function handleCreateCharacter(request: Request, env: Env): Promise<Response> {
    const payload = await extractPayload(request, env);
    if (!payload) {
        return invalidTokenResponse(env);
    }

    // Input Validation
    let body: CreateCharacterBody | null = null;
    let errorMsg: string | null = null;
    const validClasses = ['Archer', 'Warrior', 'Lancer', 'Monk', 'Adventurer'];

    try {
        body = await request.json() as CreateCharacterBody;
        if (!body.world || !body.characterName || !body.characterClass) {
            errorMsg = 'Missing required fields';
        }
        if (body.characterName.length > 32) {
            errorMsg = 'Character name too long (max 32 chars)';
        }
        if (!validClasses.includes(body.characterClass)) {
            errorMsg = 'Invalid class';
        }
        if (body.backstory && body.backstory.length > 500) {
            errorMsg = 'Backstory too long (max 500 chars)';
        }

    } catch {
        errorMsg = 'Invalid JSON body';
    }

    if (errorMsg) {
        return addCORSHeaders(
            new Response(JSON.stringify({ error: errorMsg }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            }),
            env.FRONTEND_URL
        );
    }

    const accessToken = payload.access_token;
    const username = payload.username;
    const repoOwner = 'the-real-han';
    const repoName = body?.world;

    const issuesUrl = new URL(`https://api.github.com/repos/${repoOwner}/${repoName}/issues`);
    issuesUrl.searchParams.set('state', 'open');
    issuesUrl.searchParams.set('labels', 'player');
    issuesUrl.searchParams.set('creator', username);

    const issuesResponse = await fetch(issuesUrl.toString(), {
        headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'OpenQuests Proxy'
        }
    });

    if (!issuesResponse.ok) {
        const error = await issuesResponse.json().catch(() => ({ message: issuesResponse.statusText }));
        return addCORSHeaders(
            new Response(JSON.stringify({ error: 'Failed to check existing characters', details: error }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            }),
            env.FRONTEND_URL
        );
    }

    const existingIssues = await issuesResponse.json() as any[];
    if (existingIssues.length > 0) {
        return addCORSHeaders(
            new Response(JSON.stringify({
                error: 'character_exists',
                message: 'You already have an active character.'
            }), {
                status: 409,
                headers: { 'Content-Type': 'application/json' }
            }),
            env.FRONTEND_URL
        );
    }

    // Create Issue
    const title = `🧙 Player: ${body?.characterName} (@${username})`;
    const issueBody = `## Character Name: 
${body?.characterName}
## Class: 
${body?.characterClass}

## Backstory
${body?.backstory || 'No backstory provided.'}

## Meta
GitHub: @${username}
Created via OpenQuests UI`;

    const createResponse = await fetch(`https://api.github.com/repos/${repoOwner}/${repoName}/issues`, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Accept': 'application/vnd.github.v3+json',
            'Content-Type': 'application/json',
            'User-Agent': 'OpenQuests-Auth'
        },
        body: JSON.stringify({
            title: title,
            body: issueBody,
            labels: ['player', `class:${body?.characterClass}`]
        })
    });

    if (!createResponse.ok) {
        const error = await createResponse.json().catch(() => ({ message: createResponse.statusText }));
        return addCORSHeaders(
            new Response(JSON.stringify({ error: 'Failed to create character issue', details: error }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            }),
            env.FRONTEND_URL
        );
    }

    const createdIssue = await createResponse.json() as any;

    return addCORSHeaders(
        new Response(JSON.stringify({
            issueNumber: createdIssue.number,
            characterName: body?.characterName,
            characterClass: body?.characterClass
        }), {
            status: 201,
            headers: { 'Content-Type': 'application/json' }
        }),
        env.FRONTEND_URL
    );
}
