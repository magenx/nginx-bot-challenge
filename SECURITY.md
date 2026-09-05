# Security Considerations

## JavaScript Code Exposure in Challenge Page

### Overview

The nginx-bot-challenge system serves JavaScript code directly to clients in the `/challenge` page. This is an inherent characteristic of client-side proof-of-work challenges and presents both benefits and limitations from a security perspective.

### Why Client-Side JavaScript is Exposed

**By Design**: This bot challenge system is designed to work entirely within Nginx using njs (Nginx JavaScript), without requiring external services or complex infrastructure. The challenge logic **must** run in the client's browser to:

1. Verify the client has a real JavaScript-capable browser
2. Require computational effort (proof-of-work) that is costly to automate at scale
3. Operate without backend application changes

### Security Analysis

#### ✅ What This Protects Against

1. **Simple Bots**: Basic scrapers and curl-based bots that don't execute JavaScript
2. **Low-Effort Attacks**: Attackers who don't want to invest in solving proof-of-work challenges
3. **Large-Scale Attacks**: Makes mass automation significantly more expensive (computational cost)
4. **Cookie Theft**: HMAC signatures with IP binding prevent stolen cookies from working
5. **Precomputation and Replay**: Nonces are signed and bound to the client IP and a short time window, so a solution cannot be computed ahead of time or replayed from elsewhere

#### ⚠️ Limitations and What It Does NOT Protect Against

1. **Sophisticated Bots**: Advanced attackers can:
   - Read and understand the JavaScript code
   - Implement their own proof-of-work solvers
   - Run headless browsers (Puppeteer, Selenium) to execute JavaScript
   - Use real browsers in distributed networks

2. **Code Analysis**: The challenge algorithm is visible, allowing attackers to:
   - Understand exactly how the proof-of-work functions
   - Optimize their solving algorithms
   - Identify any potential weaknesses

3. **Browser Automation**: Tools like Puppeteer or Playwright can execute the JavaScript naturally, making the challenge transparent to sophisticated bots.

4. **Distributed Attacks**: While individual challenge-solving is costly, distributed botnets with real browsers can still bypass the protection.

### Why Obfuscation Provides Limited Value

**JavaScript obfuscation is NOT recommended** for the following reasons:

1. **Security Through Obscurity is Weak**: 
   - Obfuscation can always be reversed with time and effort
   - Any determined attacker can deobfuscate code
   - Creates false sense of security

2. **Maintenance Burden**:
   - Makes legitimate debugging difficult
   - Complicates updates and bug fixes
   - Reduces code readability for security audits

3. **Performance Impact**:
   - Obfuscated code often runs slower
   - Increases page load time
   - May cause browser compatibility issues

4. **The Core Algorithm Must Be Known**:
   - Proof-of-work is a public algorithm (SHA-256)
   - The nonce is provided to the client (necessary for solving), but is signed
     with the server secret and bound to the client IP and issue time, so the
     client cannot choose or reuse one
   - The difficulty level determines solving time (observable)
   - Server validates the solution, so client-side hiding provides no benefit

### Defense in Depth Strategy

Instead of relying on code obfuscation, implement **layered security**:

#### 1. Server-Side Validation (Already Implemented) ✅

```javascript
// Server validates:
// - HMAC signature with secret key
// - IP address binding
// - Timestamp validity
// - Proof-of-work correctness
// - Cookie expiration
```

**Why This Works**: Even if attackers understand the client code, they cannot forge valid responses without:
- Solving the proof-of-work (computationally expensive)
- Knowing the server's secret key (for HMAC)
- Using the same IP address (IP binding)

#### 2. Proof-of-Work Difficulty Tuning

Adjust difficulty based on threat level:

Cost grows by a factor of **16** per level, and it is paid by legitimate
visitors, not just attackers. Measured at ~28,000 hashes/second (the rate a
browser achieves with `crypto.subtle.digest` awaited per attempt):

```nginx
# Normal traffic
js_var $challenge_difficulty "4";  # ~2-3 seconds

# Under attack - the practical ceiling
js_var $challenge_difficulty "5";  # ~40 seconds
```

Do **not** go higher. Difficulty 6 costs a desktop browser roughly ten minutes,
7 about three hours, and 8 around two days; low-end phones are several times
slower still. Under a severe attack, reach for rate limiting, a shorter
`$challenge_nonce_ttl`, and upstream DDoS protection rather than a difficulty
that locks out your users.

#### 3. Rate Limiting (Already Implemented) ✅

```nginx
limit_req_zone $binary_remote_addr zone=challenge_limit:10m rate=10r/s;
limit_req zone=challenge_limit burst=5 nodelay;
```

#### 4. CDN/WAF Integration (Recommended)

Combine with enterprise-grade solutions:
- **Cloudflare**: DDoS protection, WAF, bot management
- **AWS Shield + WAF**: Advanced threat protection
- **Akamai**: Bot Manager, DDoS protection
- **Imperva**: Advanced bot protection

#### 5. Monitoring and Adaptive Response

Implement detection and response:
- Monitor challenge solve rates (too fast = automated)
- Track IP reputation
- Dynamically adjust difficulty
- Block suspicious patterns

#### 6. Content Security Policy (Implemented Below) ✅

Add CSP headers to prevent injection attacks:

The module sets this itself on the challenge page, using a per-response nonce
rather than `unsafe-inline`:

```
Content-Security-Policy: default-src 'none'; script-src 'nonce-<random>';
    style-src 'nonce-<random>'; connect-src 'self'; frame-ancestors 'none';
    base-uri 'none'; form-action 'self';
```

### Recommended Security Enhancements

#### Enhanced Server-Side Validation

The current implementation validates:

1. Proof-of-work correctness, against the *current* difficulty
2. HMAC signature of the cookie, compared in constant time
3. IP binding of both the nonce and the cookie
4. Timestamp validity, with bounded clock drift
5. **Nonce authenticity** - the nonce carries
   `HMAC(random.issuedAt.clientIP, secret)`, so a client cannot invent its own
   nonce, precompute a solution before the nonce exists, reuse a nonce issued to
   another address, or redeem one after `$challenge_nonce_ttl` has elapsed.
   This is what stops a single solved pair from minting cookies indefinitely.
6. Configuration sanity - out-of-range or non-numeric settings fall back to safe
   defaults instead of disabling a check.

Remaining hardening to consider:

```javascript
// Single-use nonces. The nonce is stateless by design, so it may be redeemed
// more than once inside its TTL. Burning each nonce on first use requires
// shared state:
//
//   js_shared_dict_zone zone=used_nonces:1m timeout=600s;
//
// Note this is per-node: across un-synchronized load balancers a nonce could
// still be redeemed once per node.
```

#### Dynamic Difficulty Adjustment

```nginx
# Use Nginx variables to adjust based on traffic
map $http_user_agent $bot_difficulty {
    default "4";
    ~*bot "5";
    ~*crawler "5";
    ~*spider "5";
}

map $remote_addr $ip_reputation {
    default "4";
    # Known bad IPs from threat intelligence
    ~*1.2.3.4 "5";
}

js_var $challenge_difficulty $bot_difficulty;
```

#### Fingerprint Validation

Browser fingerprinting is **not** implemented. An earlier version collected a
fingerprint in the challenge page and sent it on every submission, but the
server never read it, so it was removed rather than left as dead weight and
needless data collection.

If you add it, make it actually count: hash the fingerprint server-side, bind
the hash into the cookie signature, and reject requests whose fingerprint
changes mid-session. Note the privacy implications, which in some jurisdictions
require disclosure or consent. Candidate signals:
- Canvas fingerprinting
- WebGL fingerprinting
- Audio context fingerprinting
- Font enumeration

### Browser Compatibility and Accessibility

**Important Considerations**:

1. **JavaScript Requirement**: This challenge requires JavaScript, which may impact:
   - Screen readers and assistive technologies
   - Users with JavaScript disabled
   - Text-only browsers

2. **WCAG Compliance**: May not meet accessibility standards (WCAG 2.1)

3. **Recommendations**:
   - Provide alternative access methods for verified users
   - Whitelist known accessibility tools
   - Document accessibility limitations
   - Consider CAPTCHA alternatives for accessibility compliance

### When This Solution is Appropriate

✅ **Good Use Cases**:
- Protecting administrative interfaces (wp-admin, etc.)
- Rate limiting API endpoints
- DDoS mitigation (temporary protection)
- Reducing automated scraping
- Protecting against simple bots

❌ **Not Suitable For**:
- Public APIs that need machine access
- Accessibility-critical services
- Real-time or latency-sensitive applications
- Sites requiring 100% bot elimination
- Legal/regulatory environments requiring WCAG compliance

### Conclusion

**Exposing JavaScript code in the challenge page is acceptable** because:

1. ✅ The security model does not depend on code secrecy
2. ✅ Server-side validation prevents forgery regardless of client knowledge
3. ✅ Proof-of-work provides computational cost barrier
4. ✅ HMAC + IP binding prevents cookie theft and replay
5. ✅ The goal is to raise the cost of automation, not make it impossible

**Remember**: This is one layer in a defense-in-depth strategy. It should be combined with:
- CDN/WAF protection
- Rate limiting
- IP reputation
- Monitoring and analytics
- Incident response procedures

### References

- [OWASP: Automated Threats to Web Applications](https://owasp.org/www-project-automated-threats-to-web-applications/)
- [RFC 8959: Secret Token URIs](https://www.rfc-editor.org/rfc/rfc8959.html)
- [Proof-of-Work Systems](https://en.wikipedia.org/wiki/Proof_of_work)
- [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

---

**Last Updated**: 2026-02-12  
**Version**: 1.0.0
