# Sigma Rule Support in vlair

vlair includes a built-in Sigma rule engine that evaluates curated detection rules against any log file during analysis.
No external backend or query language is required — rules run entirely in-process.

---

## Quick start

```bash
# Use the bundled rule pack (default in log-investigation workflow)
vlair log analyze access.log --sigma builtin

# Filter to high-severity rules only
vlair log analyze access.log --sigma builtin --sigma-min-level high

# Point at your own rules (file or directory)
vlair log analyze access.log --sigma ./custom_rules/

# Test a single rule against an event (exit 0 = match, 1 = no match)
vlair sigma test my_rule.yml event.json
echo '{"path": "/etc/passwd", "method": "GET"}' | vlair sigma test my_rule.yml -
```

Sigma evaluation is also enabled automatically in the `log-investigation` workflow, which uses the bundled pack.

```bash
vlair workflow log-investigation access.log
```

---

## Bundled rule pack

Rules live in `src/vlair/data/sigma_rules/` and are organised by category:

### `web/` — Web application attacks (13 rules)

| File | Title | Level |
|------|-------|-------|
| `admin_access_unusual_method.yml` | Admin Panel Access via Unusual HTTP Method | medium |
| `command_injection.yml` | Command Injection Attempt | high |
| `directory_enumeration.yml` | Web Directory Enumeration | low |
| `log4j_exploitation.yml` | Log4Shell Exploitation Attempt | critical |
| `null_byte_injection.yml` | Null Byte Injection in URL | medium |
| `open_redirect.yml` | Open Redirect Attempt | low |
| `path_traversal.yml` | Path Traversal Attack | high |
| `php_injection.yml` | PHP Code Injection Attempt | high |
| `proxyshell.yml` | ProxyShell Exchange Exploitation | critical |
| `scanner_useragent.yml` | Known Security Scanner User Agent | informational |
| `sensitive_file_access.yml` | Sensitive File Access Attempt | high |
| `shellshock.yml` | Shellshock Exploitation Attempt | critical |
| `spring4shell.yml` | Spring4Shell Exploitation Attempt | critical |
| `sql_injection.yml` | SQL Injection Attempt | high |
| `ssrf_attempt.yml` | Server-Side Request Forgery Attempt | high |
| `webshell_upload.yml` | Webshell Upload Attempt | critical |
| `xml_injection.yml` | XML/XXE Injection Attempt | medium |
| `xss_attempt.yml` | Cross-Site Scripting Attempt | medium |

### `auth/` — Authentication & privilege events (5 rules)

| File | Title | Level |
|------|-------|-------|
| `account_manipulation.yml` | Suspicious Account Manipulation | high |
| `brute_force_ssh.yml` | SSH Brute Force Attempt | medium |
| `cron_modification.yml` | Cron Job Modification | medium |
| `privilege_escalation.yml` | Privilege Escalation Attempt | high |
| `root_login.yml` | Direct Root Login | high |

**Attribution:** Rules are adapted from the [SigmaHQ](https://github.com/SigmaHQ/sigma) project under the
[Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License).
See `src/vlair/data/sigma_rules/LICENSE` for the full text.

---

## Sigma level → risk score mapping

| Sigma level | Score contribution | vlair severity |
|-------------|-------------------|----------------|
| informational | +5 | INFO |
| low | +15 | LOW |
| medium | +35 | MEDIUM |
| high | +65 | HIGH |
| critical | +90 | CRITICAL |

When multiple rules fire at the same level, vlair adds one finding per level (not one per match) to avoid
score inflation from bulk low-level matches. Score is capped at 100.

---

## Field map

vlair translates Sigma field names to its own normalized event schema using
`src/vlair/data/sigma_field_map.yml`.

### vlair normalized event fields

| vlair field | Description |
|-------------|-------------|
| `source_ip` | Client IP address |
| `method` | HTTP method (GET, POST, …) |
| `path` | Request URI path |
| `status` | HTTP status code |
| `user_agent` | HTTP User-Agent string |
| `referer` | HTTP Referer header |
| `size` | Response body size in bytes |
| `host` | Server hostname (syslog) |
| `process` | Process name (syslog) |
| `pid` | Process ID (syslog) |
| `message` | Log message body (syslog) |
| `user` | Authenticated username |
| `timestamp` | Event timestamp |
| `log_type` | Detected log format (`apache`, `nginx`, `syslog`) |

### Supported Sigma field aliases

The field map recognises the following Sigma / log-source aliases (mapping → vlair field):

**W3C / IIS:** `c-ip`, `cs-ip` → `source_ip`; `cs-uri-stem`, `cs-uri`, `cs-uri-query`, `uri`, `uri_path`, `uri_stem`, `url` → `path`; `cs-method`, `verb`, `http_method`, `request_method` → `method`; `cs-user-agent`, `agent`, `useragent`, `http_user_agent` → `user_agent`; `sc-status`, `response`, `http_status_code`, `http_status` → `status`; `cs-bytes`, `sc-bytes`, `bytes` → `size`; `cs-referer`, `referrer`, `http_referer` → `referer`; `cs-username` → `user`; `s-computername`, `s-ip` → `host`

**Apache / Nginx:** `clientip`, `src_ip` → `source_ip`; `request` → `path`

**Syslog / auth:** `hostname`, `syslog_hostname` → `host`; `program`, `application`, `syslog_process` → `process`; `pid` → `pid`; `msg`, `syslog_message` → `message`

To add support for additional field aliases, edit `src/vlair/data/sigma_field_map.yml` and add lines in the form `sigma_field_name: vlair_field_name`.

---

## Supported modifiers

| Modifier | Behaviour |
|----------|-----------|
| *(none)* | Case-insensitive equality |
| `contains` | Substring match (case-insensitive) |
| `startswith` | Prefix match (case-insensitive) |
| `endswith` | Suffix match (case-insensitive) |
| `re` | Regular expression search (case-insensitive) |
| `cidr` | CIDR network membership (e.g. `192.168.0.0/16`) |
| `all` | All values must match (AND instead of OR) |
| `any` | At least one value must match (default) |
| `lt` | Numeric less-than |
| `lte` | Numeric less-than-or-equal |
| `gt` | Numeric greater-than |
| `gte` | Numeric greater-than-or-equal |

Modifiers can be chained: `path\|contains\|all: ["/etc", "/passwd"]` requires the path to contain both substrings.

---

## Supported conditions

vlair evaluates the Sigma `condition` field with full operator support:

| Syntax | Meaning |
|--------|---------|
| `selection` | Named selection must match |
| `selection1 and selection2` | Both must match |
| `selection1 or selection2` | Either must match |
| `not selection` | Selection must not match |
| `1 of selection*` | At least one selection matching the glob must match |
| `all of selection*` | All selections matching the glob must match |
| `1 of them` | At least one selection in the rule must match |
| `all of them` | All selections in the rule must match |

Parentheses are supported for grouping, with standard `not > and > or` precedence.

---

## Writing custom rules

Sigma rules are standard YAML files. A minimal rule that works with vlair:

```yaml
title: Suspicious Path Traversal
id: a1b2c3d4-0000-0000-0000-000000000001
status: experimental
description: Detects path traversal attempts targeting /etc/passwd
level: high
tags:
  - attack.t1083
detection:
  selection:
    path|contains: ../etc/passwd
  condition: selection
```

### Field naming

Use vlair field names directly (`source_ip`, `path`, `method`, `status`, `user_agent`, `message`, …)
or any alias listed in the field map above.

### Rule authoring tips

1. **Start with a specific selection.** Broad conditions (e.g. `path|contains: /`) will fire on every request.
   Combine two or more predicates with `and` to reduce false positives.

2. **Set an appropriate level.** Reserve `critical` for confirmed exploit attempts with unique fingerprints
   (Log4Shell JNDI strings, ProxyShell path patterns). Use `medium` for heuristic detections.

3. **Add MITRE ATT&CK tags.** The `tags` field accepts `attack.T<id>` entries (case-insensitive).
   vlair includes these in match output, making ATT&CK pivoting straightforward.

4. **Test before deploying.** Use `vlair sigma test` to verify a rule fires (exit 0) or does not fire
   (exit 1) against a known-good event JSON before adding it to a production pack.

5. **Avoid unmapped fields.** vlair skips any rule that references a field not in the field map.
   Run `vlair log analyze --sigma ./rules/ --sigma-min-level informational` on a fixture log and
   check the `skipped_rules` list in the JSON output to catch mapping gaps.

6. **Use `re` sparingly.** Regex modifiers bypass the short-circuit optimisation and are evaluated
   against every event that has the field present. Prefer `contains`/`startswith` where possible.

### Testing a rule

```bash
# Match — should exit 0
echo '{"path": "/../../../etc/passwd", "method": "GET", "status": "200", "source_ip": "10.0.0.1"}' \
  | vlair sigma test my_rule.yml -

# No match — should exit 1
echo '{"path": "/index.html", "method": "GET", "status": "200", "source_ip": "10.0.0.1"}' \
  | vlair sigma test my_rule.yml -
```

The `vlair sigma test` command prints `MATCH` or `NO MATCH` and exits with code 0 or 1 respectively,
making it suitable for use in shell scripts and pre-commit hooks.

---

## CLI reference

```
vlair log analyze <file> [--sigma <path|builtin>] [--sigma-min-level <level>]
vlair sigma test <rule.yml> <event.json|->
```

| Flag | Default | Description |
|------|---------|-------------|
| `--sigma builtin` | — | Enable built-in rule pack |
| `--sigma <path>` | — | Load rules from a file or directory |
| `--sigma-min-level` | `low` | Minimum level to evaluate (`informational`\|`low`\|`medium`\|`high`\|`critical`) |

---

## JSON output fields

When `--sigma` is active, the `metadata` block of `vlair log analyze --json` includes:

```json
{
  "sigma_rules_loaded": 23,
  "sigma_rules_evaluated": 21,
  "skipped_rules": [
    {"path": "rules/my_rule.yml", "rule_id": "...", "reason": "unmapped fields: CommandLine"}
  ]
}
```

Each Sigma match in the `alerts` array has `"source": "sigma"` and these additional fields:

```json
{
  "source": "sigma",
  "rule_id": "...",
  "rule_name": "SQL Injection Attempt",
  "level": "high",
  "mitre_attack": ["T1190"],
  "tags": ["attack.t1190"],
  "rule_link": "https://...",
  "match_count": 3,
  "matched_event": { ... }
}
```
