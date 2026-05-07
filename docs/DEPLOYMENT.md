# vlair Deployment Security Checklist

Production deployment guide covering secrets, networking, database, and operational security.

---

## 1. Environment Variables (Required)

| Variable | Purpose | Example |
|----------|---------|---------|
| `VLAIR_SECRET_KEY` | JWT signing key. App refuses to start if default value is detected with `FLASK_ENV=production`. | `python -c "import secrets; print(secrets.token_hex(32))"` |
| `FLASK_ENV` | Set to `production` to enable startup guards and disable debug mode. | `production` |
| `VT_API_KEY` | VirusTotal API key (optional, enables hash/domain/URL intel). | |
| `ABUSEIPDB_KEY` | AbuseIPDB API key (optional, enables IP reputation). | |
| `ANTHROPIC_API_KEY` | Anthropic API key (optional, enables AI analysis). | |
| `OPENAI_API_KEY` | OpenAI API key (optional, alternative AI provider). | |

**Never commit `.env` files.** Use your deployment platform's secret management (e.g., Vault, AWS Secrets Manager, Azure Key Vault).

---

## 2. HTTPS / TLS

- Terminate TLS at a reverse proxy (Nginx, Caddy, or cloud load balancer). Do **not** expose Flask directly.
- Use TLS 1.2+ only. Disable SSLv3, TLS 1.0, TLS 1.1.
- The app sets `Strict-Transport-Security` automatically when `request.is_secure` is true.
- Redirect all HTTP traffic to HTTPS at the proxy level.

### Reverse proxy configuration (required for HSTS)

The app uses `werkzeug.middleware.proxy_fix.ProxyFix(x_proto=1, x_host=1)`, which trusts **exactly one** upstream proxy hop. This is required for `request.is_secure` to reflect the original client's protocol when Flask is behind a TLS-terminating proxy.

If your deployment adds more proxy layers (e.g., a cloud load balancer in front of Nginx), increment the hop count in `create_app()` accordingly:

```python
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=2, x_host=2)  # two hops
```

**Do not set `x_proto` higher than the actual number of trusted proxy hops** — over-trusting allows clients to spoof `X-Forwarded-Proto`.

### Example Nginx snippet

```nginx
server {
    listen 443 ssl;
    server_name vlair.example.com;

    ssl_certificate     /etc/ssl/certs/vlair.crt;
    ssl_certificate_key /etc/ssl/private/vlair.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name vlair.example.com;
    return 301 https://$host$request_uri;
}
```

---

## 3. Database Permissions

vlair uses SQLite databases stored in `~/.vlair/`:

| Database | Purpose |
|----------|---------|
| `~/.vlair/webapp.db` | Users, roles, API keys, audit log, revoked tokens |
| `~/.vlair/investigations.db` | Investigation state and results |
| `~/.vlair/ai_cache.db` | AI response cache |

**Hardening:**
- Run the app under a dedicated service account (e.g., `vlair`).
- Set permissions: `chmod 700 ~/.vlair && chmod 600 ~/.vlair/*.db`
- Back up databases regularly. SQLite supports online backup via `.backup` command.
- For multi-instance deployments, consider migrating to PostgreSQL.

---

## 4. File Upload and Path Restrictions

- Upload limit is **16 MB** (`MAX_CONTENT_LENGTH`).
- User-supplied file paths are validated against an allowlist: system temp directory and `~/.vlair/` only.
- Uploaded files are stored in the system temp directory with randomized names.
- Ensure the temp directory has adequate disk space and is on a partition separate from the OS if possible.

---

## 5. Authentication and Token Security

- **JWT access tokens** expire after 1 hour (default). Adjust via application config if needed.
- **Token revocation** is enforced via a SQLite blocklist checked on every request.
- **API keys** are hashed with per-key PBKDF2 salt (100k iterations).
- **Rate limiting** on auth endpoints: 10 requests per 5-minute window per IP.
- **MFA (TOTP)** is available and recommended for all admin accounts.

---

## 6. HTTP Security Headers

The following headers are set automatically on every response:

| Header | Value |
|--------|-------|
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `X-XSS-Protection` | `1; mode=block` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; ...` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` (HTTPS only) |

---

## 7. Reverse Proxy Configuration

- Set `X-Forwarded-For` and `X-Forwarded-Proto` headers at the proxy.
- Limit request body size at the proxy level as a defense-in-depth measure.
- Consider connection rate limiting at the proxy level in addition to application-level rate limiting.
- Do **not** expose Flask's built-in server (`flask run`) in production. Use Gunicorn or uWSGI:

```bash
pip install gunicorn
gunicorn "vlair.webapp.app:create_app()" --bind 127.0.0.1:5000 --workers 4
```

---

## 8. Monitoring and Audit

- **Audit log**: All authenticated requests are logged to `webapp.db` with user, action, IP, and user agent.
- Forward application logs to your SIEM or log aggregator.
- Monitor for:
  - Repeated 401/403 responses (credential stuffing, privilege escalation attempts)
  - 429 responses (rate limit hits)
  - 413 responses (oversized upload attempts)
  - Unusual API key creation or MFA disable events

---

## 9. Pre-Launch Checklist

- [ ] `VLAIR_SECRET_KEY` is set to a unique, random 32+ byte hex string
- [ ] `FLASK_ENV=production` is set
- [ ] TLS is terminated at reverse proxy with TLS 1.2+ only
- [ ] HTTP redirects to HTTPS
- [ ] Database files have `600` permissions owned by service account
- [ ] `~/.vlair/` directory has `700` permissions
- [ ] WSGI server (Gunicorn/uWSGI) is used instead of Flask dev server
- [ ] Admin accounts have MFA enabled
- [ ] Firewall restricts access to Flask port (only reverse proxy can reach it)
- [ ] Log forwarding is configured
- [ ] Backup schedule is in place for SQLite databases
- [ ] `.env` file is not present on the server (secrets injected via environment)

---

*Last updated: 2026-03-24*
