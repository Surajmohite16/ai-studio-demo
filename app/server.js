
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import session from 'express-session';
import cors from 'cors';
import bodyParser from 'body-parser';

import { SignJWT, generateKeyPair, exportJWK } from 'jose';
import { v4 as uuidv4 } from 'uuid';
import dotenv from 'dotenv';


if (fs.existsSync('.env')) {
    dotenv.config();
} else {
    console.log('No .env file found, assuming environment variables are injected.');
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Configuration
const PORT = process.env.PORT || 5173;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// In development: use localhost/host.docker.internal for Docker compatibility
// In production: use the production domain
const PRODUCTION_DOMAIN = process.env.PRODUCTION_DOMAIN || 'ai-studio.opendesignschool.ac.in';
const OIDC_ISSUER = IS_PRODUCTION
    ? (process.env.OIDC_ISSUER || `https://${PRODUCTION_DOMAIN}`)
    : `http://host.docker.internal:${PORT}`;
const PARENT_ORIGIN = IS_PRODUCTION
    ? (process.env.PARENT_ORIGIN || `https://${PRODUCTION_DOMAIN}`)
    : `http://localhost:${PORT}`;

// Cognito Configuration
const COGNITO_ISSUER = process.env.COGNITO_ISSUER;
const COGNITO_CLIENT_ID = process.env.COGNITO_CLIENT_ID;
const COGNITO_CLIENT_SECRET = process.env.COGNITO_CLIENT_SECRET;
const COGNITO_REDIRECT_URI = process.env.COGNITO_REDIRECT_URI;
const COGNITO_AUTHORIZATION_ENDPOINT = process.env.COGNITO_AUTHORIZATION_ENDPOINT;
const COGNITO_TOKEN_ENDPOINT = process.env.COGNITO_TOKEN_ENDPOINT;
const COGNITO_USERINFO_ENDPOINT = process.env.COGNITO_USERINFO_ENDPOINT;

// In-memory store for authorization codes
// WARNING: In production, use Redis or a database for persistence
// Server restart will invalidate all active sessions
const authCodes = new Map();
// In-memory store for access tokens (needed for userinfo endpoint)
const accessTokenMap = new Map();

// Generate Keys on Startup (In prod, load from secrets)
// We need RS256 for OIDC usually
let privateKey, publicKey, jwks;
const KID = uuidv4(); // Generate unique Key ID per session to safely invalidate client caches

async function generateKeys() {
    const { privateKey: priv, publicKey: pub } = await generateKeyPair('RS256');
    privateKey = priv;
    publicKey = pub;
    const jwk = await exportJWK(pub);
    jwks = { keys: [{ ...jwk, kid: KID, use: 'sig', alg: 'RS256' }] };
    console.log('Keys generated with KID:', KID);
}

async function createServer() {
    await generateKeys();

    const app = express();
    app.use(cors({
        origin: PARENT_ORIGIN,
        credentials: true
    }));
    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({ extended: true }));

    // Session middleware
    app.use(session({
        secret: process.env.SESSION_SECRET || 'dev-secret-change-in-production',
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: false, // Set to true in production with HTTPS
            httpOnly: true,
            maxAge: parseInt(process.env.SESSION_LIFETIME_MS || '86400000') // Default 24 hours
        }
    }));

    // --- User Authentication Endpoints (Backend Proxy) ---

    // 1. Login - Redirect to Cognito
    app.get('/auth/login', (req, res) => {
        const state = uuidv4();
        req.session.oauthState = state;

        const authUrl = new URL(COGNITO_AUTHORIZATION_ENDPOINT);
        authUrl.searchParams.set('client_id', COGNITO_CLIENT_ID);
        authUrl.searchParams.set('response_type', 'code');
        authUrl.searchParams.set('scope', 'openid email profile');
        authUrl.searchParams.set('redirect_uri', COGNITO_REDIRECT_URI);
        authUrl.searchParams.set('state', state);

        console.log('Auth: Redirecting to Cognito for login');
        res.redirect(authUrl.toString());
    });

    // 2. Callback - Handle OAuth callback from Cognito
    app.get('/auth/callback', async (req, res) => {
        const { code, state } = req.query;

        // Validate state to prevent CSRF
        if (!state || state !== req.session.oauthState) {
            console.error('Auth: Invalid state parameter');
            return res.status(400).send('Invalid state parameter');
        }

        if (!code) {
            console.error('Auth: No authorization code received');
            return res.status(400).send('No authorization code received');
        }

        try {
            // Exchange code for tokens
            const tokenResponse = await fetch(COGNITO_TOKEN_ENDPOINT, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    grant_type: 'authorization_code',
                    client_id: COGNITO_CLIENT_ID,
                    client_secret: COGNITO_CLIENT_SECRET,
                    code: code,
                    redirect_uri: COGNITO_REDIRECT_URI,
                }),
            });

            if (!tokenResponse.ok) {
                const errorText = await tokenResponse.text();
                console.error('Auth: Token exchange failed:', errorText);
                throw new Error('Token exchange failed');
            }

            const tokens = await tokenResponse.json();

            // Fetch user info
            const userInfoResponse = await fetch(COGNITO_USERINFO_ENDPOINT, {
                headers: {
                    'Authorization': `Bearer ${tokens.access_token}`,
                },
            });

            if (!userInfoResponse.ok) {
                throw new Error('Failed to fetch user info');
            }

            const userInfo = await userInfoResponse.json();

            // Store user in session
            req.session.user = {
                ...userInfo,
                access_token: tokens.access_token,
                id_token: tokens.id_token,
            };

            console.log('Auth: User logged in:', userInfo.email);

            // Redirect to dashboard
            res.redirect('/');
        } catch (error) {
            console.error('Auth: Callback error:', error.message);
            res.status(500).send('Authentication failed');
        }
    });

    // 3. Get current user
    app.get('/auth/user', (req, res) => {
        if (!req.session.user) {
            return res.status(401).json({ error: 'Not authenticated' });
        }

        res.json({
            profile: req.session.user,
            access_token: req.session.user.access_token,
            id_token: req.session.user.id_token,
        });
    });

    // 4. Logout
    app.post('/auth/logout', (req, res) => {
        const email = req.session.user?.email;
        req.session.destroy((err) => {
            if (err) {
                console.error('Auth: Logout error:', err);
                return res.status(500).json({ error: 'Logout failed' });
            }
            console.log('Auth: User logged out:', email);
            res.json({ success: true });
        });
    });

    // --- OIDC Provider Endpoints ---

    // 1. Discovery
    app.get('/.well-known/openid-configuration', (req, res) => {
        res.json({
            issuer: OIDC_ISSUER,
            authorization_endpoint: `${PARENT_ORIGIN}/auth/authorize`, // Browser-facing
            token_endpoint: `${OIDC_ISSUER}/auth/token`,
            jwks_uri: `${OIDC_ISSUER}/jwks.json`,
            userinfo_endpoint: `${OIDC_ISSUER}/auth/userinfo`,
            response_types_supported: ['code'],
            subject_types_supported: ['public'],
            id_token_signing_alg_values_supported: ['RS256'],
        });
    });

    // 2. JWKS
    app.get('/jwks.json', (req, res) => {
        res.json(jwks);
    });

    // 3. Authorization (The Handshake)
    // Penpot redirects iframe here. We serve a page that talks to the Parent.

    // Internal helper to create code (called by the frontend script above)
    app.post('/auth/generate-code', (req, res) => {
        const { redirect_uri, state, user_claims, access_token, client_id, nonce } = req.body;

        if (access_token) {
            console.log('Bridge: Validating token with Cognito...');
            // Use the custom domain endpoint from discovery doc
            fetch(COGNITO_USERINFO_ENDPOINT, {
                headers: { 'Authorization': `Bearer ${access_token}` }
            })
                .then(async (cognitoRes) => {
                    if (!cognitoRes.ok) {
                        const errorText = await cognitoRes.text();
                        console.error('Bridge: Cognito Error Status:', cognitoRes.status);
                        console.error('Bridge: Cognito Error Body:', errorText);
                        throw new Error(`Cognito validation failed: ${cognitoRes.status} ${errorText}`);
                    }
                    const freshClaims = await cognitoRes.json();
                    console.log('Bridge: Cognito validation success for:', freshClaims.email);

                    // Proceed with fresh claims
                    const code = uuidv4();
                    authCodes.set(code, { user_claims: freshClaims, client_id, nonce }); // Store client_id and nonce

                    const url = new URL(redirect_uri);
                    url.searchParams.set('code', code);
                    if (state) url.searchParams.set('state', state);

                    res.json({ redirect_url: url.toString() });
                })
                .catch(err => {
                    console.error('Bridge: Validation Error:', err.message);
                    res.status(401).json({ error: 'upstream_validation_failed' });
                });
        } else {
            // Fallback (Not recommended for prod, but kept for resiliency)
            console.warn('Bridge: No access_token provided, skipping validation (INSECURE)');
            const code = uuidv4();
            authCodes.set(code, { user_claims, client_id, nonce }); // Store client_id and nonce

            // Return the full redirect URL
            const url = new URL(redirect_uri);
            url.searchParams.set('code', code);
            if (state) url.searchParams.set('state', state);

            res.json({ redirect_url: url.toString() });
        }
    });

    // 4. Token Endpoint (Called by Penpot Backend)
    app.post('/auth/token', async (req, res) => {
        const { code, grant_type } = req.body;
        console.log('Bridge: /auth/token called with code:', code);

        if (grant_type !== 'authorization_code') {
            return res.status(400).json({ error: 'unsupported_grant_type' });
        }

        const data = authCodes.get(code);
        if (!data) {
            console.error('Bridge: Invalid or expired code');
            return res.status(400).json({ error: 'invalid_code' });
        }

        authCodes.delete(code); // One-time use

        // Generate Tokens
        // Generate Access Token and store claims
        const accessToken = uuidv4();
        accessTokenMap.set(accessToken, data.user_claims);

        // ID Token (JWT)
        const idToken = await new SignJWT({
            sub: data.user_claims.sub || 'unknown',
            name: data.user_claims.name || data.user_claims.email,
            email: data.user_claims.email,
            email_verified: true,
            nonce: data.nonce, // Include nonce if present
            // Add other claims as needed
        })
            .setProtectedHeader({ alg: 'RS256', kid: KID })
            .setIssuedAt()
            .setIssuer(OIDC_ISSUER) // Must match discovery
            .setAudience(data.client_id || 'penpot') // Dynamic Audience
            .setExpirationTime(`${process.env.OIDC_TOKEN_TTL_SEC || 3600}s`)
            .sign(privateKey);

        res.json({
            access_token: accessToken,
            id_token: idToken,
            token_type: 'Bearer',
            expires_in: parseInt(process.env.OIDC_TOKEN_TTL_SEC || '3600'),
        });
    });

    // 5. UserInfo (Now Implemented)
    app.get('/auth/userinfo', (req, res) => {
        const authHeader = req.headers.authorization;
        if (!authHeader) return res.status(401).json({ error: 'no_token' });

        const token = authHeader.split(' ')[1];
        const user = accessTokenMap.get(token);

        if (!user) {
            console.error('Bridge: Token not found in map:', token);
            return res.status(401).json({ error: 'invalid_token' });
        }

        res.json({
            sub: user.sub || 'unknown',
            name: user.name || user.email,
            email: user.email,
            email_verified: true,
            picture: user.picture
        });
    });


    if (process.env.NODE_ENV === 'production') {
        // Serve static files from dist
        app.use(express.static(path.join(__dirname, 'dist')));

        // SPA fallback
        app.get(/(.*)/, (req, res) => {
            res.sendFile(path.join(__dirname, 'dist', 'index.html'));
        });
    } else {
        // --- Vite Middleware Integration ---
        const { createServer: createViteServer } = await import('vite');
        const vite = await createViteServer({
            server: { middlewareMode: true },
            appType: 'spa',
        });

        app.use(vite.middlewares);
    }

    app.listen(PORT, () => {
        console.log(`Server running at http://localhost:${PORT}`);
        console.log(`OIDC Issuer: ${OIDC_ISSUER}`);
    });
}

createServer();
