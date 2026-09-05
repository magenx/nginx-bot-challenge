# Nginx Bot Challenge

A bot protection system using Nginx's built-in njs (Nginx JavaScript) module. Provides bot protection without requiring external modules, using a JavaScript proof-of-work challenge, HMAC-SHA256 signed nonces, and HMAC-SHA256 signed, IP-bound cookies.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Nginx](https://img.shields.io/badge/nginx-%3E%3D1.25.1-brightgreen.svg)]()
[![njs](https://img.shields.io/badge/njs-%3E%3D0.7.0-brightgreen.svg)]()

> **⚠️ FAQ: Is it safe to show JavaScript code in the challenge page?**  
> **YES! ✅** The JavaScript code is intentionally visible by design. Security is based on server-side cryptographic validation (HMAC + IP binding), not code secrecy. [Read the full explanation →](docs/ANSWER_JS_CODE_SAFETY.md)

## Features

✅ **No External Dependencies** - Uses only Nginx's built-in njs module  
✅ **Proof-of-Work Challenge** - Requires real browser computation (SHA-256, configurable difficulty)  
✅ **Signed Nonces** - Every challenge is bound to the issuing server, the client IP, and a short time window, so a solution cannot be precomputed or replayed  
✅ **HMAC-SHA256 Cookies** - Cryptographic validation of challenge cookies, compared in constant time  
✅ **IP Binding** - Cookies are tied to the client address  
✅ **Fails Closed** - A missing, weak, or placeholder secret disables the challenge endpoint rather than silently accepting traffic  
✅ **Native Whitelisting** - Uses Nginx's `geo` and `map` modules; a bypass requires a trusted source address *and* an expected User-Agent  
✅ **Rate Limiting** - Prevent brute force attempts  
✅ **Strict CSP** - Per-response nonce, no `unsafe-inline`  
✅ **CDN & Varnish Compatible** - Works behind reverse proxies with the right cache headers

## Requirements

- Nginx with the njs module (`--with-http_js_module`)
- njs 0.7.0 or newer
- **HTTPS.** The challenge cookie is issued with the `Secure` attribute on HTTPS requests. Serve the challenge over TLS; over plain HTTP browsers discard `Secure` cookies and clients loop on the challenge forever.

## Installation

### 1. Install Nginx with njs Module

#### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install nginx nginx-module-njs
nginx -V 2>&1 | grep -o js  # Verify installation
```

#### RHEL/CentOS/Rocky Linux

```bash
sudo yum install nginx nginx-module-njs
# Or: sudo dnf install nginx nginx-module-njs
nginx -V 2>&1 | grep -o js  # Verify installation
```

#### Alpine Linux

```bash
sudo apk add nginx nginx-mod-http-js
nginx -V 2>&1 | grep -o js  # Verify installation
```

### 2. Install Bot Challenge Files

```bash
# Clone this repository
git clone https://github.com/magenx/nginx-bot-challenge.git
cd nginx-bot-challenge

# Copy the njs module to the Nginx directory
sudo mkdir -p /etc/nginx/njs
sudo cp njs/challenge.js /etc/nginx/njs/
sudo chmod 644 /etc/nginx/njs/challenge.js

# Backup existing configuration
sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
```

### 3. Configure Nginx

Edit `/etc/nginx/nginx.conf`. A complete, working example lives in [`conf/nginx.conf`](conf/nginx.conf).

```nginx
# Load njs module at the top
load_module modules/ngx_http_js_module.so;

http {
    # Import the njs module
    js_path "/etc/nginx/njs/";
    js_import challenge from challenge.js;

    # Configuration variables.
    # IMPORTANT: generate a strong secret with `openssl rand -base64 32`.
    # The module refuses to run with an empty, short (<32 chars), or placeholder secret.
    js_var $challenge_secret "YOUR-GENERATED-SECRET-KEY-HERE";
    js_var $challenge_duration "3600";      # Cookie validity in seconds (1 hour)
    js_var $challenge_difficulty "4";       # Proof-of-work difficulty
    js_var $challenge_nonce_ttl "600";      # How long an issued challenge may be redeemed

    js_set $challenge_valid challenge.validateChallenge;

    # --- Whitelisting (see "Whitelist Configuration" below) ---
    geo $trusted_source {
        default 0;
        127.0.0.1/32 1;
        ::1/128      1;
    }

    map $http_user_agent $monitor_ua {
        default 0;
        "~*ELB-HealthChecker" 1;
        "~*GoogleHC"          1;
        "~*kube-probe"        1;
    }

    # A bypass requires a trusted source address AND an expected User-Agent.
    map "$trusted_source$monitor_ua" $bypass_whitelist {
        default 0;
        "11"    1;
    }

    # One decision variable. Nginx does not allow nested `if`, so combine
    # the two signals in a map instead.
    map "$bypass_whitelist$challenge_valid" $need_challenge {
        default 1;    # not whitelisted, no valid cookie -> challenge
        "~^1"   0;    # whitelisted
        "01"    0;    # valid challenge cookie
    }

    server {
        listen 443 ssl;
        http2 on;                      # nginx >= 1.25.1; older: listen 443 ssl http2;
        server_name example.com;

        ssl_certificate     /etc/nginx/ssl/example.com.crt;
        ssl_certificate_key /etc/nginx/ssl/example.com.key;

        root /var/www/html;
        index index.html;

        # Challenge submission endpoint. Required on every server that
        # serves the challenge page - the page posts its solution here.
        location = /challenge {
            client_max_body_size 2k;
            js_content challenge.verifyProofOfWork;
        }

        # Protected content
        location / {
            if ($need_challenge) {
                js_content challenge.serveChallenge;
            }

            try_files $uri $uri/ =404;
        }
    }
}
```

### 4. Generate Secret Key

```bash
# Generate a strong random secret key
openssl rand -base64 32

# Update nginx.conf with the generated key
# js_var $challenge_secret "OUTPUT-FROM-ABOVE-COMMAND";
```

### 5. Test and Reload

```bash
sudo nginx -t
sudo systemctl reload nginx
sudo systemctl status nginx
```

## Configuration

### Core Parameters

Configure using `js_var` directives in `nginx.conf`.

Every numeric value is range-checked. If a value is missing, non-numeric, or outside its range, the module logs an error and falls back to its built-in default — it never silently disables a check.

#### `$challenge_secret` (Required)

Secret key for HMAC-SHA256 signatures. Must be at least 32 characters and must not be one of the placeholder strings shipped in this repository.

```nginx
js_var $challenge_secret "YOUR-VERY-SECRET-AND-RANDOM-KEY-HERE";
```

**Security:** Generate using `openssl rand -base64 32`. If this is unset, too short, or still a placeholder, the module logs an error and refuses to issue or accept challenges — every request is treated as unverified.

#### `$challenge_duration`

How long the challenge cookie remains valid, in seconds.

**Module default:** `21600` (6 hours) · **Range:** 300 – 86400

```nginx
js_var $challenge_duration "7200";  # 2 hours
```

#### `$challenge_difficulty`

Number of leading hex zeros required in the proof-of-work hash. Each extra level multiplies the work by **16**.

**Default:** `4` · **Range:** 1 – 8

```nginx
js_var $challenge_difficulty "5";
```

#### `$challenge_nonce_ttl`

How long an issued challenge may be redeemed, in seconds. Must comfortably exceed the solve time at your configured difficulty, or slow clients will be told to reload.

**Default:** `600` (10 minutes) · **Range:** 60 – 3600

```nginx
js_var $challenge_nonce_ttl "600";
```

### Difficulty Levels

Solving is `O(16^difficulty)` hashes. Times below assume roughly **28,000 hashes/second**, measured with `crypto.subtle.digest` awaited per attempt — the approach the challenge page uses. Low-end phones are commonly 2–5× slower.

| Level | Expected hashes | Approx. desktop time | Use case |
|-------|-----------------|----------------------|----------|
| 3 | 4,096 | < 1s | Light friction only |
| 4 | 65,536 | ~2–3s | **Recommended default** |
| 5 | 1,048,576 | ~40s | High security; noticeable wait |
| 6 | 16,777,216 | ~10 minutes | ❌ Not usable — locks out real users |
| 7 | 268,435,456 | ~3 hours | ❌ Not usable |
| 8 | 4,294,967,296 | ~2 days | ❌ Not usable |

> **Do not raise the difficulty above 5.** The cost is exponential and falls entirely on legitimate visitors. Under attack, prefer rate limiting, a shorter `$challenge_nonce_ttl`, and upstream DDoS protection.

Raising the difficulty also invalidates cookies minted at a lower difficulty, so existing visitors are re-challenged.

### Whitelist Configuration

Whitelisting is handled by Nginx's native `geo` and `map` modules rather than in JavaScript. `geo` uses a radix tree in C, handles IPv4 and IPv6 CIDR correctly, and costs no JavaScript call per request.

> **A User-Agent proves nothing.** It is set by the client, so `curl -A UptimeRobot` would bypass every check. A bypass therefore requires **both** a trusted source address **and** an expected User-Agent.

```nginx
# Source addresses you trust: your own IPs, internal load balancers,
# and the published ranges of your monitoring providers.
geo $trusted_source {
    default 0;
    127.0.0.1/32   1;
    ::1/128        1;
    10.0.0.0/8     1;    # internal network / k8s probes
    203.0.113.7/32 1;    # your office IP
}

# User-Agents used by health checks and monitoring services.
map $http_user_agent $monitor_ua {
    default 0;
    "~*ELB-HealthChecker" 1;
    "~*GoogleHC"          1;
    "~*kube-probe"        1;
    "~*UptimeRobot"       1;
    "~*Pingdom"           1;
    "~*StatusCake"        1;
}

map "$trusted_source$monitor_ua" $bypass_whitelist {
    default 0;
    "11"    1;    # trusted source AND expected monitoring User-Agent
    # "10"  1;    # uncomment to let trusted sources bypass unconditionally
}
```

To whitelist **your own** access regardless of User-Agent, add your IP to `geo` and uncomment the `"10"` line.

## Use Cases

Full working versions of all of these are in [`conf/nginx.conf`](conf/nginx.conf). They all rely on the `geo`/`map` blocks above being present in the `http` context.

### 1. Protect WordPress Admin

```nginx
server {
    listen 443 ssl;
    server_name wordpress.example.com;

    ssl_certificate     /etc/nginx/ssl/wordpress.example.com.crt;
    ssl_certificate_key /etc/nginx/ssl/wordpress.example.com.key;

    root /var/www/wordpress;

    # Required: the challenge page posts its solution here.
    location = /challenge {
        client_max_body_size 2k;
        js_content challenge.verifyProofOfWork;
    }

    location /wp-admin/ {
        if ($need_challenge) {
            js_content challenge.serveChallenge;
        }

        location ~ \.php$ {
            include fastcgi_params;
            fastcgi_pass unix:/var/run/php/php-fpm.sock;
        }
    }

    location = /wp-login.php {
        if ($need_challenge) {
            js_content challenge.serveChallenge;
        }

        include fastcgi_params;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
    }
}
```

### 2. Protect API Endpoints

API clients cannot run JavaScript, so return an error rather than the challenge page. A browser-based client obtains its cookie by visiting a challenged HTML page first.

```nginx
server {
    listen 443 ssl;
    server_name api.example.com;

    ssl_certificate     /etc/nginx/ssl/api.example.com.crt;
    ssl_certificate_key /etc/nginx/ssl/api.example.com.key;

    location = /challenge {
        client_max_body_size 2k;
        js_content challenge.verifyProofOfWork;
    }

    # Public health check (no challenge).
    # default_type sets the content type; add_header Content-Type would
    # append a duplicate header instead of replacing it.
    location /health {
        default_type text/plain;
        return 200 'OK';
    }

    location /api/ {
        if ($need_challenge) {
            return 403 '{"error":"Challenge required"}';
        }

        proxy_pass http://backend;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 3. DDoS Mitigation

```nginx
limit_req_zone $binary_remote_addr zone=ddos:10m rate=1r/s;

server {
    listen 443 ssl;
    server_name protected.example.com;

    ssl_certificate     /etc/nginx/ssl/protected.example.com.crt;
    ssl_certificate_key /etc/nginx/ssl/protected.example.com.key;

    root /var/www/html;

    # Raise difficulty for this server only. Keep it at 5 or below:
    # difficulty 6 costs a browser roughly ten minutes.
    js_var $challenge_difficulty "5";

    location = /challenge {
        limit_req zone=ddos burst=5 nodelay;
        client_max_body_size 2k;
        js_content challenge.verifyProofOfWork;
    }

    location / {
        limit_req zone=ddos burst=5 nodelay;

        if ($need_challenge) {
            js_content challenge.serveChallenge;
        }

        try_files $uri $uri/ =404;
    }
}
```

### 4. Selective Path Protection

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/nginx/ssl/example.com.crt;
    ssl_certificate_key /etc/nginx/ssl/example.com.key;

    root /var/www/html;

    location = /challenge {
        client_max_body_size 2k;
        js_content challenge.verifyProofOfWork;
    }

    location /admin/ {
        if ($need_challenge) {
            js_content challenge.serveChallenge;
        }
        try_files $uri $uri/ =404;
    }

    # Static assets (no challenge needed).
    # A regex location takes precedence over the "/" prefix location.
    location ~* \.(css|js|jpg|png|gif|ico|svg|woff2)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

## Customization

### Customize the Challenge Page

Edit the HTML/CSS in the `serveChallenge()` function in `njs/challenge.js`.

The page carries a strict Content-Security-Policy with a per-response nonce and no `unsafe-inline`. If you add your own `<style>` or `<script>` element, give it `nonce="${cspNonce}"` or the browser will refuse to run it. External resources are blocked by `default-src 'none'` — extend the CSP if you need them.

### Adjust Difficulty Dynamically

```nginx
map $http_user_agent $bot_difficulty {
    default "4";
    ~*bot     "5";
    ~*crawler "5";
}

js_var $challenge_difficulty $bot_difficulty;
```

If the map produces an empty or non-numeric value, the module logs an error and falls back to its default of 4.

### Add Custom Validation Logic

Edit `njs/challenge.js`:

```javascript
function validateChallenge(r) {
    // ... existing validation ...

    const userAgent = r.headersIn['User-Agent'] || '';
    if (userAgent.includes('BadBot')) {
        r.warn('bot-challenge: blocked known bad bot');
        return '0';
    }

    // ... rest of validation ...
}
```

## Security

### Security Features

✅ **Signed nonces** - A challenge is bound to the server secret, the client IP, and a time window, so solutions cannot be precomputed or replayed  
✅ **HMAC-SHA256 cookies** - Prevents cookie forgery; compared in constant time  
✅ **IP binding** - Cookies are tied to the client address  
✅ **Timestamp validation** - Bounded cookie lifetime with clock-drift tolerance  
✅ **Proof-of-work** - Requires computational effort per client  
✅ **Fail-closed configuration** - Invalid settings fall back to safe defaults; an unsafe secret disables the system loudly  
✅ **Rate limiting** - Prevents brute force  
✅ **Strict CSP** - Per-response nonce, no `unsafe-inline`

### JavaScript Code Exposure

⚠️ The challenge JavaScript is intentionally exposed to clients. This is **by design and safe** because:

1. **Server-side validation** ensures security — the server validates every solution with a secret key
2. **Proof-of-work remains costly** — knowing the algorithm does not make it cheaper to compute
3. **Nonces are signed and short-lived** — a solution cannot be precomputed or reused across clients
4. **Security through obscurity is avoided** — the system does not rely on hiding the algorithm

See **[SECURITY.md](SECURITY.md)** for the full analysis.

### Best Practices

1. **Strong secret key** — `openssl rand -base64 32`
2. **Serve over HTTPS** — required for the `Secure` cookie attribute
3. **Set the real client IP** when behind a proxy or CDN, or every client shares the proxy's address:
   ```nginx
   set_real_ip_from 10.0.0.0/8;
   real_ip_header X-Forwarded-For;
   ```
4. **Keep difficulty at 4–5** and enable rate limiting
5. **Synchronize clocks** across nodes (NTP), and share one secret

### Known Limitations

⚠️ **Limitations:**
- Not effective against distributed botnets driving real browsers
- A determined attacker can solve the proof-of-work programmatically; the signed nonce raises the cost per cookie but does not eliminate it
- Requires JavaScript (accessibility concern — a `<noscript>` message is shown)
- Client-side code is visible and can be analyzed
- Nonces are stateless, so a nonce may be redeemed more than once within its TTL. Preventing this entirely requires shared state (`js_shared_dict_zone`), which does not survive across un-synchronized load-balanced nodes.

**Recommendation:** Combine with CDN-level DDoS protection (Cloudflare, AWS Shield), a WAF, and IP reputation services. This system is one layer in a defense-in-depth strategy.

## Troubleshooting

### 1. "njs module not found"

```bash
nginx -V 2>&1 | grep js
sudo apt-get install nginx-module-njs  # Ubuntu/Debian
sudo yum install nginx-module-njs      # RHEL/CentOS
```

### 2. "js_import: cannot locate module"

```nginx
js_path "/etc/nginx/njs/";
```

```bash
ls -la /etc/nginx/njs/          # should show challenge.js
sudo chmod 644 /etc/nginx/njs/challenge.js
```

### 3. `"if" directive is not allowed here`

Nginx does not support nested `if` blocks. Combine the whitelist and challenge signals in a `map` and use a single `if ($need_challenge)`, as shown above.

### 4. Challenge loop (page keeps re-appearing)

The most common cause is the cookie being discarded:

- **Serving over plain HTTP.** The cookie is issued with `Secure` on HTTPS requests. If you terminate TLS upstream, forward `X-Forwarded-Proto: https` so the module knows the connection is secure.
- **Client IP changes between requests** (multiple egress IPs, or a proxy whose real IP is not configured). Set `set_real_ip_from` / `real_ip_header`.
- **Missing `/challenge` location** on that server — the page has nowhere to post its solution. Check for 404s on `POST /challenge`.
- Third-party cookie blocking, or JavaScript disabled.

### 5. "Challenge expired or not issued to you, please reload"

The nonce's TTL elapsed before the client finished solving, or the client's IP changed mid-solve. Raise `$challenge_nonce_ttl` or lower `$challenge_difficulty`.

### 6. Errors in the log about the secret

```
bot-challenge: $challenge_secret is unset, shorter than 32 characters, or still a placeholder
```

The module is refusing to run. Generate a real secret with `openssl rand -base64 32`.

### 7. Diagnostics are missing from the log

The module logs at `warn` and `error`. Ensure your `error_log` level is `warn` or lower:

```nginx
error_log /var/log/nginx/error.log warn;
```

### 8. "getRandomValues is not a function"

njs has different crypto APIs than Node.js:

- `require('crypto')` in njs provides `createHash()` and `createHmac()` only
- `crypto.getRandomValues()` is available on the **global** `crypto` object (Web Crypto API)

```javascript
crypto.getRandomValues(bytes);            // correct

const crypto = require('crypto');
crypto.getRandomValues(bytes);            // fails
```

Reference: https://github.com/nginx/njs-examples/blob/master/njs/misc/aes_gcm.js

### 9. Verifying that a client is actually challenged

```bash
# Should return the challenge page HTML, not your content
curl -A "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X)" https://your-domain.com/

# A spoofed monitoring UA from an untrusted IP should also be challenged
curl -A "UptimeRobot/2.0" https://your-domain.com/
```

If a client is unexpectedly bypassing, check whether its address matches your `geo $trusted_source` block, and whether it already holds a valid cookie.

## Performance

The per-request cost of a validated client is one HMAC-SHA256 plus one SHA-256 over short strings, in-process in njs — small relative to normal request handling, but measure on your own hardware rather than relying on a published figure.

Two things matter more than micro-optimization:

1. **Do not reference `$challenge_valid` in your `log_format`.** It is a `js_set` variable, so putting it in the default access log forces the validation to run for *every* logged request, including static assets and health checks. Use a separate debug format while troubleshooting only.
2. **Exclude static assets** from the challenged location, as the examples do.

Proof-of-work solving is the dominant cost and is paid by the client — see the difficulty table above.

## Browser Compatibility

**Compatible with:** current Chrome, Firefox, Safari, Edge, and mobile browsers (iOS Safari, Chrome Mobile, Android Browser).

- Mobile devices **are** challenged by default; there is no automatic bypass.
- Solving may take several times longer on low-end phones. Difficulty 4 is comfortable; see the difficulty table.

**Requirements:** Web Crypto API (`crypto.subtle`), JavaScript enabled, cookies enabled.

## Varnish Cache Compatibility

The system sets `Cache-Control: no-store, no-cache, must-revalidate, private`, `Pragma`, `Expires`, and `Surrogate-Control: no-store` on challenge responses, and the example configuration adds `Vary: Cookie` to protected locations.

```vcl
sub vcl_backend_response {
    if (beresp.http.Cache-Control ~ "no-store" ||
        beresp.http.Cache-Control ~ "no-cache" ||
        beresp.http.Cache-Control ~ "private") {
        set beresp.uncacheable = true;
        set beresp.ttl = 0s;
        return (deliver);
    }

    if (beresp.http.Surrogate-Control ~ "no-store") {
        set beresp.uncacheable = true;
        set beresp.ttl = 0s;
        return (deliver);
    }
    # Varnish respects Vary: Cookie by default.
}

sub vcl_recv {
    if (req.url ~ "^/challenge") {
        return (pass);
    }
}
```

```bash
curl -I https://your-domain.com/ | grep -i "x-cache\|cache-control"
curl -I -X POST https://your-domain.com/challenge | grep -i "x-cache\|cache-control"
```

## FAQ

**Q: Will this work with Cloudflare/CDN?**  
A: Yes. Configure `set_real_ip_from` and `real_ip_header` so `$remote_addr` is the true client IP — nonces and cookies are bound to it. Without this, every client shares the CDN's address.

**Q: Does this work with load balancers?**  
A: Yes, but all nodes must share the same secret and have synchronized clocks.

**Q: What about mobile browsers?**  
A: They are challenged like desktop browsers. There is no automatic mobile bypass. See [docs/MOBILE_DEVICES.md](docs/MOBILE_DEVICES.md).

**Q: How do I bypass the challenge for my own access?**  
A: Add your IP to the `geo $trusted_source` block and uncomment the `"10"` line in the `$bypass_whitelist` map.

**Q: Can a bot just replay a solved challenge?**  
A: Not indefinitely. Each nonce is signed with the server secret, the client IP, and an issue time, and is only redeemable within `$challenge_nonce_ttl`. A solution cannot be precomputed before the nonce is issued, reused from another IP, or replayed after the TTL.

**Q: Can I customize the challenge page?**  
A: Yes — edit the HTML in `serveChallenge()` in `njs/challenge.js`. Remember the CSP nonce (see Customization).

## Files

```
nginx-bot-challenge/
├── njs/
│   └── challenge.js          # Challenge module (serve, verify, validate)
├── conf/
│   └── nginx.conf            # Example configuration (verified with nginx -t)
├── docs/
│   ├── ANSWER_JS_CODE_SAFETY.md   # JavaScript code exposure explanation
│   └── MOBILE_DEVICES.md          # Mobile device configuration guide
├── README.md                 # This file
├── SECURITY.md               # Security considerations
└── LICENSE                   # MIT License
```

## Upgrading

Recent changes are **breaking** for existing deployments:

1. **`njs/whitelist.js` is removed.** Delete `/etc/nginx/njs/whitelist.js`, drop the `js_import whitelist ...` and `js_set $bypass_whitelist whitelist.shouldBypassChallenge;` lines, and add the `geo`/`map` blocks shown above.
2. **User-Agent-only bypass no longer works.** A whitelisted request now needs a trusted source address as well. Add your monitors' IP ranges to `geo $trusted_source`.
3. **Nested `if` blocks must be replaced** with the `$need_challenge` map — the previous examples could not start nginx.
4. **The secret is now enforced.** An empty, short, or placeholder `$challenge_secret` disables the system with an error in the log.
5. **The nonce format changed.** Challenge pages already open in a browser must be reloaded once; cookies already issued remain valid until they expire.
6. **Serve over HTTPS** (or forward `X-Forwarded-Proto: https`).

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by [nginx-javascript-challenge-module](https://github.com/nginx-modules/nginx-javascript-challenge)
- Built with [njs](https://nginx.org/en/docs/njs/) - Nginx JavaScript
- Challenge algorithm based on proof-of-work systems

---

**Made with ❤️ for the Nginx community**
