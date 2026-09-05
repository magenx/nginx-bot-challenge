# Mobile Device Handling

This document explains how the nginx-bot-challenge system handles mobile devices and how to configure mobile-specific behavior.

## Default Behavior

**Mobile devices ARE challenged by default.**

The bot challenge system treats mobile browsers (iOS Safari, Android Chrome, etc.) the same as desktop browsers — they must complete the proof-of-work challenge to access protected content.

This is intentional for security reasons:
- Mobile bot traffic is significant and growing
- Mobile malware and automated attacks are common
- Bypassing mobile devices creates a large security hole

## Solve Time on Mobile

Proof-of-work cost is `16^difficulty` hashes and is paid entirely by the client. Phones are commonly 2–5× slower than a desktop:

| Difficulty | Desktop (~28k H/s) | Low-end phone (~6k H/s) |
|-----------|--------------------|-------------------------|
| 3 | < 1s | ~1s |
| 4 | ~2–3s | ~10s |
| 5 | ~40s | ~3 minutes |
| 6 | ~10 minutes | ~45 minutes |

**Keep difficulty at 4 for general traffic.** If a large share of your audience is on older phones, consider 3. Difficulty 6 and above is unusable on mobile.

Also make sure `$challenge_nonce_ttl` (default 600s) comfortably exceeds the slowest expected solve time, or slow phones will be told the challenge expired and asked to reload.

## Why Mobile Clients Might Not See the Challenge

If you're accessing your site on a mobile device and NOT seeing the challenge when you expect to, check these common causes:

### 1. Valid Challenge Cookie

Your mobile device may have a valid challenge cookie from a previous visit. The challenge is shown once per `$challenge_duration` (module default: 6 hours).

**Solution:** Clear your browser cookies and try again.

### 2. Source IP Is Trusted

Whitelisting is configured in `nginx.conf` with the `geo` module. A bypass requires the request to come from a trusted source address **and** carry an expected monitoring User-Agent, so a mobile browser is only exempt if its network is listed:

```nginx
geo $trusted_source {
    default 0;
    127.0.0.1/32 1;
    10.0.0.0/8   1;    # would also cover devices on this network
}
```

**Check:** whether the device's public IP falls inside a range in your `geo $trusted_source` block.

### 3. A Mobile User-Agent Was Added to the Monitor Map

```nginx
map $http_user_agent $monitor_ua {
    default 0;
    "~*ELB-HealthChecker" 1;
    # A pattern like "~*Mobile" here would match phones.
}
```

**Check:** that no pattern in `$monitor_ua` matches ordinary mobile browsers. Note this alone is not enough to bypass — the source IP must also be trusted.

### 4. Configuration Issue

Your nginx configuration might not be enforcing the challenge correctly.

**Verify:** your `nginx.conf` combines the two signals in a map and uses a single `if`. Nginx does **not** allow nested `if` blocks — a config with them will not start.

```nginx
map "$bypass_whitelist$challenge_valid" $need_challenge {
    default 1;
    "~^1"   0;
    "01"    0;
}

location / {
    if ($need_challenge) {
        js_content challenge.serveChallenge;
    }

    try_files $uri $uri/ =404;
}
```

## Testing Mobile Enforcement

```bash
# Should return the challenge page HTML, not your content
curl -A "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X)" https://your-domain.com/

# Android
curl -A "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120 Mobile" https://your-domain.com/
```

Check the error log for the reason behind unexpected behavior:

```bash
sudo tail -f /var/log/nginx/error.log
```

The module logs at `warn` and `error`, so ensure your `error_log` level is `warn` or lower.

## How to Bypass Mobile Clients (Not Recommended)

Bypassing by User-Agent alone is not possible by design: a User-Agent is chosen by the client, so any bot can claim to be an iPhone. `curl -A "...iPhone..."` would sail straight through.

If you have a genuine need to exempt mobile devices, scope it to networks you control — for example a corporate mobile range:

```nginx
geo $trusted_source {
    default 0;
    203.0.113.0/24 1;    # your corporate mobile network
}

map $http_user_agent $monitor_ua {
    default 0;
    "~*Mobile.*Safari" 1;
    "~*Android.*Mobile" 1;
}

# Requires BOTH: a device on your network AND a mobile User-Agent.
map "$trusted_source$monitor_ua" $bypass_whitelist {
    default 0;
    "11"    1;
}
```

A better answer for slow devices is usually to lower `$challenge_difficulty` to 3, which keeps every client verified while cutting the solve time by 16×.

## Browser Compatibility

The challenge requires the Web Crypto API (`crypto.subtle`), which is available in:

- iOS Safari 11+
- Android Chrome 37+
- Samsung Internet 6+
- Firefox for Android

**Note:** `crypto.subtle` is only exposed in secure contexts (HTTPS). This is another reason the challenge must be served over TLS — over plain HTTP the challenge cannot run at all, and the `Secure` cookie it issues would be discarded anyway.

Clients with JavaScript disabled see a `<noscript>` message explaining that JavaScript is required.

## Related Documentation

- [README.md](../README.md) - Main documentation
- [SECURITY.md](../SECURITY.md) - Security considerations
- [challenge.js](../njs/challenge.js) - Challenge module
- [conf/nginx.conf](../conf/nginx.conf) - Example configuration, including the `geo`/`map` whitelist
