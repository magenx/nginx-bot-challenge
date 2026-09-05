/**
 * Nginx Bot Challenge - njs Module
 *
 * Provides bot protection using a JavaScript proof-of-work challenge,
 * HMAC-SHA256 signed nonces, and HMAC-SHA256 signed, IP-bound cookies.
 *
 * @author nginx-bot-challenge
 * @license MIT
 */

/**
 * Configuration defaults - can be overridden via js_var in nginx.conf.
 * Values coming from nginx variables are always range-checked (see getIntConfig)
 * so that a typo in the configuration can never disable a security check.
 */
const CONFIG = {
    COOKIE_NAME: '__bot_challenge',
    DURATION: 21600,          // Cookie validity in seconds (6 hours)
    DIFFICULTY: 4,            // Number of leading hex zeros required in PoW
    NONCE_TTL: 600,           // How long an issued nonce may be redeemed (10 minutes)
    MAX_TIMESTAMP_DRIFT: 300  // Allow 5 minutes of clock drift
};

/** Accepted ranges for operator-supplied values. Out-of-range falls back to CONFIG. */
const LIMITS = {
    DURATION: { min: 300, max: 86400 },
    DIFFICULTY: { min: 1, max: 8 },
    NONCE_TTL: { min: 60, max: 3600 }
};

/** nginx variable backing each configuration key. */
const CONFIG_VARS = {
    DURATION: 'challenge_duration',
    DIFFICULTY: 'challenge_difficulty',
    NONCE_TTL: 'challenge_nonce_ttl'
};

/** A secret shorter than this, or matching a shipped placeholder, is refused. */
const MIN_SECRET_LENGTH = 32;
const PLACEHOLDER_SECRETS = [
    'change-this-secret-key',
    'change-this-to-a-random-secret-key-min-32-chars',
    'YOUR-GENERATED-SECRET-KEY-HERE',
    'YOUR-VERY-SECRET-AND-RANDOM-KEY-HERE'
];

/**
 * Compiled once at module load: getCookie() runs on every single request.
 * Anchored on a cookie boundary so that a cookie merely *ending* in the
 * configured name (e.g. "evil__bot_challenge") cannot shadow the real one.
 */
const COOKIE_RE = new RegExp('(?:^|;\\s*)' + CONFIG.COOKIE_NAME + '=([^;]*)');

/** Wire-format guards. The nonce uses "." internally so it never collides
 *  with the ":" separator of the cookie. */
const NONCE_RE = /^[0-9a-f]{32}\.[0-9]{1,15}\.[0-9a-f]{32}$/;
const SOLUTION_RE = /^[0-9]{1,20}$/;

/**
 * Extract the challenge cookie value from the request
 * @param {NginxHTTPRequest} r - Nginx request object
 * @returns {string|null} Cookie value or null if not found
 */
function getCookie(r) {
    const match = (r.headersIn.Cookie || '').match(COOKIE_RE);
    return match ? decodeURIComponent(match[1]) : null;
}

/**
 * Resolve the shared secret, refusing to run with an unsafe one.
 * @param {NginxHTTPRequest} r - Nginx request object
 * @returns {string|null} The secret, or null when it is unusable
 */
function getSecret(r) {
    const secret = r.variables.challenge_secret || '';

    if (secret.length < MIN_SECRET_LENGTH || PLACEHOLDER_SECRETS.indexOf(secret) !== -1) {
        r.error('bot-challenge: $challenge_secret is unset, shorter than ' + MIN_SECRET_LENGTH +
                ' characters, or still a placeholder - refusing to issue or accept challenges. ' +
                'Generate one with: openssl rand -base64 32');
        return null;
    }

    return secret;
}

/**
 * Read an integer setting from an nginx variable, with range checking.
 *
 * This must never return NaN: '0'.repeat(NaN) is '' and ''.startsWith() is
 * always true, which would silently disable the proof-of-work check entirely.
 *
 * @param {NginxHTTPRequest} r - Nginx request object
 * @param {string} key - Configuration key (must exist in CONFIG_VARS)
 * @returns {number} A validated integer, never NaN
 */
function getIntConfig(r, key) {
    const varName = CONFIG_VARS[key];
    const fallback = CONFIG[key];
    const raw = r.variables[varName];

    if (!raw) {
        return fallback;
    }

    const value = parseInt(raw, 10);
    const limit = LIMITS[key];

    if (isNaN(value) || value < limit.min || value > limit.max) {
        r.error(`bot-challenge: $${varName} is "${raw}", expected an integer in ` +
                `${limit.min}..${limit.max} - falling back to ${fallback}`);
        return fallback;
    }

    return value;
}

/**
 * Compare two strings without leaking their contents through timing.
 * njs has no crypto.timingSafeEqual, so accumulate the difference.
 * @param {string} a - First string
 * @param {string} b - Second string
 * @returns {boolean} True if the strings are equal
 */
function constantTimeEquals(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) {
        return false;
    }

    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }

    return diff === 0;
}

/**
 * Generate HMAC-SHA256 signature
 * @param {string} message - Message to sign
 * @param {string} secret - Secret key
 * @returns {string} Hex-encoded signature
 */
function hmacSHA256(message, secret) {
    const crypto = require('crypto');
    return crypto.createHmac('sha256', secret).update(message).digest('hex');
}

/**
 * Generate SHA-256 hash
 * @param {string} data - Data to hash
 * @returns {string} Hex-encoded hash
 */
function sha256(data) {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Client address used for binding nonces and cookies.
 * Behind a proxy or CDN, configure set_real_ip_from / real_ip_header so that
 * $remote_addr is the true client address.
 * @param {NginxHTTPRequest} r - Nginx request object
 * @returns {string} Client IP address
 */
function clientIP(r) {
    return r.variables.remote_addr || r.remoteAddress || '';
}

/**
 * Generate a random hex string.
 * Uses the Web Crypto API's getRandomValues(), available in njs as a global
 * crypto object (not the Node.js-style require('crypto') module).
 * @param {number} byteLength - Number of random bytes
 * @returns {string} Hex string of length byteLength * 2
 */
function randomHex(byteLength) {
    const bytes = new Uint8Array(byteLength);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Issue a self-verifying nonce: random.issuedAt.tag
 *
 * The tag binds the nonce to this server's secret, to the issuing time, and to
 * the client address. Without it a client could invent its own nonce, solve one
 * proof-of-work once, and replay that pair forever to mint unlimited cookies.
 * Being self-verifying, it needs no shared state and works across load-balanced
 * nodes that share the secret.
 *
 * @param {NginxHTTPRequest} r - Nginx request object
 * @param {string} secret - Secret key
 * @returns {string} Signed nonce
 */
function issueNonce(r, secret) {
    const random = randomHex(16);
    const issuedAt = Math.floor(Date.now() / 1000);
    const tag = hmacSHA256(`${random}.${issuedAt}.${clientIP(r)}`, secret).substring(0, 32);

    return `${random}.${issuedAt}.${tag}`;
}

/**
 * Verify a nonce was issued by this server, to this client, recently enough.
 * @param {NginxHTTPRequest} r - Nginx request object
 * @param {string} nonce - Nonce submitted by the client
 * @param {string} secret - Secret key
 * @param {number} ttl - Maximum nonce age in seconds
 * @returns {boolean} True if the nonce is valid
 */
function verifyNonce(r, nonce, secret, ttl) {
    if (!NONCE_RE.test(nonce)) {
        return false;
    }

    const parts = nonce.split('.');
    const random = parts[0];
    const issuedAt = parseInt(parts[1], 10);
    const tag = parts[2];

    const expected = hmacSHA256(`${random}.${issuedAt}.${clientIP(r)}`, secret).substring(0, 32);
    if (!constantTimeEquals(tag, expected)) {
        return false;
    }

    const now = Math.floor(Date.now() / 1000);
    if (issuedAt > now + CONFIG.MAX_TIMESTAMP_DRIFT) {
        return false;
    }

    return now - issuedAt <= ttl;
}

/**
 * Whether the request reached us over TLS.
 * The Secure cookie attribute must not be set on a plain HTTP response, or the
 * browser silently discards the cookie and the client re-challenges forever.
 * @param {NginxHTTPRequest} r - Nginx request object
 * @returns {boolean} True if the request is HTTPS
 */
function isSecureRequest(r) {
    if (r.variables.https) {
        return true;
    }

    const forwarded = r.headersIn['X-Forwarded-Proto'];
    if (typeof forwarded !== 'string') {
        return false;
    }

    return forwarded.split(',')[0].trim().toLowerCase() === 'https';
}

/**
 * Make an untrusted string safe to write to the error log (no CR/LF injection,
 * bounded length).
 * @param {string} value - Untrusted value
 * @param {number} maxLength - Maximum length to keep
 * @returns {string} Sanitized value
 */
function sanitizeForLog(value, maxLength) {
    return String(value).replace(/[^\x20-\x7e]/g, '.').substring(0, maxLength);
}

/**
 * Validate challenge cookie
 * @param {NginxHTTPRequest} r - Nginx request object
 * @returns {string} "1" if valid, "0" if invalid
 */
function validateChallenge(r) {
    const secret = getSecret(r);
    if (!secret) {
        return '0';
    }

    const cookie = getCookie(r);
    if (!cookie) {
        return '0';
    }

    // Parse cookie: timestamp:nonce:solution:signature
    const parts = cookie.split(':');
    if (parts.length !== 4) {
        return '0';
    }

    const timestamp = parts[0];
    const nonce = parts[1];
    const solution = parts[2];
    const signature = parts[3];

    // Validate timestamp
    const now = Math.floor(Date.now() / 1000);
    const cookieTime = parseInt(timestamp, 10);
    const duration = getIntConfig(r, 'DURATION');

    if (isNaN(cookieTime) || cookieTime > now + CONFIG.MAX_TIMESTAMP_DRIFT) {
        return '0';
    }

    if (now - cookieTime > duration) {
        return '0';
    }

    // Verify signature (binds the cookie to this client's address)
    const message = `${timestamp}:${nonce}:${solution}:${clientIP(r)}`;
    if (!constantTimeEquals(signature, hmacSHA256(message, secret))) {
        r.warn('bot-challenge: invalid cookie signature');
        return '0';
    }

    // Re-verify the proof of work. The signature already proves this server
    // accepted it once, but re-checking against the *current* difficulty is
    // what invalidates cookies minted at a lower difficulty when an operator
    // raises it under attack. Do not remove this as a micro-optimization.
    const difficulty = getIntConfig(r, 'DIFFICULTY');
    if (!sha256(nonce + solution).startsWith('0'.repeat(difficulty))) {
        return '0';
    }

    return '1';
}

/**
 * Set common headers for JSON responses.
 * Prevents caching by Varnish and other proxies.
 * @param {NginxHTTPRequest} r - Nginx request object
 * @returns {void}
 */
function setJsonResponseHeaders(r) {
    r.headersOut['Content-Type'] = 'application/json';
    r.headersOut['Cache-Control'] = 'no-store, no-cache, must-revalidate, private, max-age=0';
    r.headersOut['Pragma'] = 'no-cache';
    r.headersOut['Expires'] = '0';
}

/**
 * Send a JSON error response
 * @param {NginxHTTPRequest} r - Nginx request object
 * @param {number} status - HTTP status code
 * @param {string} message - Error message
 * @returns {void}
 */
function jsonError(r, status, message) {
    setJsonResponseHeaders(r);
    r.return(status, JSON.stringify({ error: message }));
}

/**
 * Verify proof of work solution submitted by client
 * @param {NginxHTTPRequest} r - Nginx request object
 * @returns {void}
 */
function verifyProofOfWork(r) {
    const MAX_BODY_SIZE = 1024;

    if (r.method !== 'POST') {
        r.headersOut['Allow'] = 'POST';
        jsonError(r, 405, 'Method not allowed');
        return;
    }

    const secret = getSecret(r);
    if (!secret) {
        jsonError(r, 500, 'Server misconfigured');
        return;
    }

    // r.requestText was introduced in njs 0.5.0; r.requestBody was removed in 0.8.0.
    // It is undefined when nginx buffered the body to a temp file, which the
    // client_max_body_size on this location prevents.
    const body = r.requestText || '';

    if (body.length === 0) {
        jsonError(r, 400, 'Empty request body');
        return;
    }

    if (body.length > MAX_BODY_SIZE) {
        jsonError(r, 413, 'Request body too large');
        return;
    }

    let data;
    try {
        data = JSON.parse(body);
    } catch (e) {
        jsonError(r, 400, 'Malformed JSON');
        return;
    }

    if (data === null || typeof data !== 'object') {
        jsonError(r, 400, 'Expected a JSON object');
        return;
    }

    try {
        const nonce = data.nonce;
        const solution = data.solution;

        if (typeof nonce !== 'string' || !NONCE_RE.test(nonce) ||
            typeof solution !== 'string' || !SOLUTION_RE.test(solution)) {
            jsonError(r, 400, 'Malformed nonce or solution');
            return;
        }

        // The nonce must be one we issued, to this client, recently. Without
        // this check a single precomputed (nonce, solution) pair would mint
        // cookies forever and the proof of work would cost an attacker nothing.
        const nonceTtl = getIntConfig(r, 'NONCE_TTL');
        if (!verifyNonce(r, nonce, secret, nonceTtl)) {
            jsonError(r, 403, 'Challenge expired or not issued to you, please reload');
            return;
        }

        // Verify proof of work
        const difficulty = getIntConfig(r, 'DIFFICULTY');
        if (!sha256(nonce + solution).startsWith('0'.repeat(difficulty))) {
            jsonError(r, 403, 'Invalid proof of work');
            return;
        }

        // Soft anomaly detection: a hash rate far beyond what a browser's
        // Web Crypto API achieves suggests a native or precomputed solver.
        // Logged only - the signed nonce above is the real defence.
        const solveTime = data.solveTime;
        const attempts = data.attempts;
        if (typeof solveTime === 'number' && typeof attempts === 'number' &&
            solveTime > 0 && attempts > 0) {
            const MAX_REALISTIC_HASH_RATE = 1000000;
            const hashesPerSecond = attempts / (solveTime / 1000);

            if (hashesPerSecond > MAX_REALISTIC_HASH_RATE) {
                r.warn(`bot-challenge: unrealistic hash rate ${hashesPerSecond.toFixed(0)} H/s ` +
                       `from ${clientIP(r)} (difficulty ${difficulty})`);
            }
        }

        // Issue the signed, IP-bound cookie
        const timestamp = Math.floor(Date.now() / 1000);
        const signature = hmacSHA256(`${timestamp}:${nonce}:${solution}:${clientIP(r)}`, secret);
        const cookieValue = `${timestamp}:${nonce}:${solution}:${signature}`;
        const duration = getIntConfig(r, 'DURATION');

        let cookieHeader = `${CONFIG.COOKIE_NAME}=${encodeURIComponent(cookieValue)}` +
                           `; Path=/; Max-Age=${duration}; HttpOnly; SameSite=Lax`;
        if (isSecureRequest(r)) {
            cookieHeader += '; Secure';
        }

        r.headersOut['Set-Cookie'] = cookieHeader;
        setJsonResponseHeaders(r);
        r.return(200, JSON.stringify({ success: true, message: 'Challenge completed' }));
    } catch (e) {
        r.error('bot-challenge: error processing challenge: ' + (e.stack || e.message || e));
        jsonError(r, 500, 'Internal server error');
    }
}

/**
 * Serve challenge page to client
 * @param {NginxHTTPRequest} r - Nginx request object
 * @returns {void}
 */
function serveChallenge(r) {
    const secret = getSecret(r);
    if (!secret) {
        r.return(500, 'Bot challenge is misconfigured');
        return;
    }

    const nonce = issueNonce(r, secret);
    const difficulty = getIntConfig(r, 'DIFFICULTY');
    // Distinct from the proof-of-work nonce: this one lets the CSP allow our
    // own inline <style>/<script> without resorting to 'unsafe-inline'.
    const cspNonce = randomHex(16);

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Check</title>
    <style nonce="${cspNonce}">
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: #fefefe;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .challenge-container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 40px;
            max-width: 500px;
            width: 100%;
            text-align: center;
        }

        .logo {
            font-size: 48px;
            margin-bottom: 20px;
        }

        h1 {
            font-size: 24px;
            color: #333;
            margin-bottom: 10px;
        }

        .subtitle {
            color: #666;
            font-size: 14px;
            margin-bottom: 30px;
        }

        .loader {
            width: 48px;
            height: 48px;
            display: inline-block;
            position: relative;
            transform: rotate(45deg);
        }

        .loader::before {
            content: '';
            box-sizing: border-box;
            width: 24px;
            height: 24px;
            position: absolute;
            left: 0;
            top: -24px;
            animation: animloader 4s ease infinite;
        }

        .loader::after {
            content: '';
            box-sizing: border-box;
            position: absolute;
            left: 0;
            top: 0;
            width: 24px;
            height: 24px;
            background: linear-gradient(135deg, #6fcf97, #27ae60, #1e8449);
            box-shadow: 0 0 15px rgba(39, 174, 96, 0.5);
            animation: animloader2 2s ease infinite;
        }

        @keyframes animloader {
            0% {
                box-shadow: 0 24px rgba(111, 207, 151, 0), 24px 24px rgba(111, 207, 151, 0), 24px 48px rgba(111, 207, 151, 0), 0px 48px rgba(111, 207, 151, 0);
            }
            12% {
                box-shadow: 0 24px #6fcf97, 24px 24px rgba(111, 207, 151, 0), 24px 48px rgba(111, 207, 151, 0), 0px 48px rgba(111, 207, 151, 0);
            }
            25% {
                box-shadow: 0 24px #6fcf97, 24px 24px #27ae60, 24px 48px rgba(111, 207, 151, 0), 0px 48px rgba(111, 207, 151, 0);
            }
            37% {
                box-shadow: 0 24px #6fcf97, 24px 24px #27ae60, 24px 48px #1e8449, 0px 48px rgba(111, 207, 151, 0);
            }
            50% {
                box-shadow: 0 24px #6fcf97, 24px 24px #27ae60, 24px 48px #1e8449, 0px 48px #1e8449;
            }
            62% {
                box-shadow: 0 24px rgba(111, 207, 151, 0), 24px 24px #27ae60, 24px 48px #1e8449, 0px 48px #1e8449;
            }
            75% {
                box-shadow: 0 24px rgba(111, 207, 151, 0), 24px 24px rgba(111, 207, 151, 0), 24px 48px #1e8449, 0px 48px #1e8449;
            }
            87% {
                box-shadow: 0 24px rgba(111, 207, 151, 0), 24px 24px rgba(111, 207, 151, 0), 24px 48px rgba(111, 207, 151, 0), 0px 48px #1e8449;
            }
            100% {
                box-shadow: 0 24px rgba(111, 207, 151, 0), 24px 24px rgba(111, 207, 151, 0), 24px 48px rgba(111, 207, 151, 0), 0px 48px rgba(111, 207, 151, 0);
            }
        }

        @keyframes animloader2 {
            0% {
                transform: translate(0, 0) rotateX(0) rotateY(0);
            }
            25% {
                transform: translate(100%, 0) rotateX(0) rotateY(180deg);
            }
            50% {
                transform: translate(100%, 100%) rotateX(-180deg) rotateY(180deg);
            }
            75% {
                transform: translate(0, 100%) rotateX(-180deg) rotateY(360deg);
            }
            100% {
                transform: translate(0, 0) rotateX(0) rotateY(360deg);
            }
        }

        @media (prefers-reduced-motion: reduce) {
            .loader::before,
            .loader::after {
                animation: none;
            }
        }

        .status {
            color: #666;
            font-size: 14px;
            margin-top: 15px;
        }

        .error {
            color: #d32f2f;
            margin-top: 15px;
            padding: 10px;
            background: #ffebee;
            border-radius: 4px;
            display: none;
        }

        .success {
            color: #388e3c;
            font-size: 16px;
            margin-top: 15px;
        }

        .info {
            margin-top: 20px;
            padding: 15px;
            background: #f5f5f5;
            border-radius: 8px;
            font-size: 12px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="challenge-container">
        <div class="logo">🛡️</div>
        <h1>Security Check</h1>
        <p class="subtitle">Please wait while we verify your browser...</p>

        <div class="loader"></div>

        <div class="status" id="status" role="status" aria-live="polite">Initializing challenge...</div>
        <div class="error" id="error" role="alert"></div>

        <noscript>
            <div class="error" style="display:block">
                This security check requires JavaScript. Please enable JavaScript and reload the page.
            </div>
        </noscript>

        <div class="info">
            This security check helps us protect against automated bots and malicious traffic.
            The process should complete in a few seconds.
        </div>
    </div>

    <script nonce="${cspNonce}">
        const NONCE = '${nonce}';
        const DIFFICULTY = ${difficulty};

        const statusEl = document.getElementById('status');
        const errorEl = document.getElementById('error');

        function showError(message) {
            errorEl.textContent = 'Error: ' + message;
            errorEl.style.display = 'block';
        }

        // SHA-256 hash function using Web Crypto API
        async function sha256(message) {
            const msgBuffer = new TextEncoder().encode(message);
            const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
            return Array.from(new Uint8Array(hashBuffer))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
        }

        // Proof of work computation
        async function solveChallenge(nonce, difficulty) {
            const prefix = '0'.repeat(difficulty);
            // 16^difficulty is the expected number of attempts; allow generous
            // headroom, then give up rather than spinning forever.
            const maxAttempts = Math.pow(16, difficulty) * 20;
            const startCounter = Math.floor(Math.random() * 1e9);
            const startTime = performance.now();

            let counter = startCounter;
            let lastYield = startTime;

            statusEl.textContent = 'Computing proof of work...';

            while (counter - startCounter < maxAttempts) {
                const hash = await sha256(nonce + counter.toString());

                if (hash.startsWith(prefix)) {
                    const solveTime = Math.round(performance.now() - startTime);
                    statusEl.textContent = \`Challenge solved in \${(solveTime / 1000).toFixed(2)}s! Redirecting...\`;
                    return {
                        solution: counter.toString(),
                        solveTime: solveTime,
                        attempts: counter - startCounter
                    };
                }

                counter++;

                // Yield on a time budget rather than a fixed attempt count, so
                // slow devices stay responsive and fast ones are not throttled.
                const now = performance.now();
                if (now - lastYield > 100) {
                    lastYield = now;
                    statusEl.textContent = \`Challenge calculation: \${(counter - startCounter).toLocaleString()}...\`;
                    await new Promise(resolve => setTimeout(resolve, 0));
                }
            }

            throw new Error('Could not solve the challenge in a reasonable time. Please reload the page.');
        }

        // Submit solution to server
        async function submitSolution(result) {
            const response = await fetch('/challenge', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    nonce: NONCE,
                    solution: result.solution,
                    solveTime: result.solveTime,
                    attempts: result.attempts
                })
            });

            const contentType = response.headers.get('content-type');
            if (!contentType || !contentType.includes('application/json')) {
                throw new Error('Server returned an invalid response. Please try again.');
            }

            let data;
            try {
                data = await response.json();
            } catch (e) {
                throw new Error('Server returned invalid JSON. Please try again.');
            }

            if (!response.ok || !data.success) {
                throw new Error(data.error || 'Failed to verify solution');
            }

            statusEl.textContent = '✓ Verification complete!';
            statusEl.className = 'status success';

            setTimeout(() => { window.location.reload(); }, 1000);
        }

        // Main challenge flow
        async function runChallenge() {
            try {
                if (!window.crypto || !window.crypto.subtle) {
                    throw new Error('Your browser does not support required cryptographic features');
                }

                await submitSolution(await solveChallenge(NONCE, DIFFICULTY));
            } catch (error) {
                showError(error.message);
                statusEl.textContent = '✕ Verification failed';
            }
        }

        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', runChallenge);
        } else {
            runChallenge();
        }
    </script>
</body>
</html>`;

    r.headersOut['Content-Type'] = 'text/html; charset=utf-8';
    // Prevent Varnish and other caching proxies from caching the challenge page
    r.headersOut['Cache-Control'] = 'no-store, no-cache, must-revalidate, private, max-age=0';
    r.headersOut['Pragma'] = 'no-cache';
    r.headersOut['Expires'] = '0';
    r.headersOut['Surrogate-Control'] = 'no-store';

    // Security headers. The CSP nonce covers our own inline style and script,
    // so no 'unsafe-inline' is needed.
    r.headersOut['Content-Security-Policy'] =
        `default-src 'none'; script-src 'nonce-${cspNonce}'; style-src 'nonce-${cspNonce}'; ` +
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self';";
    r.headersOut['X-Frame-Options'] = 'DENY';
    r.headersOut['X-Content-Type-Options'] = 'nosniff';
    r.headersOut['Referrer-Policy'] = 'no-referrer';

    r.return(200, html);
}

// Export functions for use in nginx.conf
export default { validateChallenge, serveChallenge, verifyProofOfWork };
