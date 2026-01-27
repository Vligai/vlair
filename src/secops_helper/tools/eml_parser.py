#!/usr/bin/env python3
"""
EML Parser - Email analysis and security assessment

Parses .eml email files to extract:
- Headers (From, To, Subject, Date, Message-ID)
- Authentication results (SPF, DKIM, DMARC)
- IP addresses from Received headers
- Attachments with file hashes
- Body content and embedded URLs

Optional VirusTotal integration for attachment reputation checks.

Usage:
    secops eml suspicious.eml --vt
    secops eml phishing.eml --output report.json
"""

import eml_parser
import json
import os
import sys
import requests
import argparse
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")


def json_serial(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


def parse_eml(file_path):
    with open(file_path, "rb") as f:
        raw_email = f.read()
    parser = eml_parser.EmlParser(include_raw_body=True)
    return parser.decode_email_bytes(raw_email)


def extract_basic_headers(parsed):
    header = parsed.get("header", {})
    raw = header.get("header", {})

    return {
        "From": header.get("from", "N/A"),
        "To": header.get("to", ["N/A"]),
        "Subject": header.get("subject", "N/A"),
        "Date": header.get("date", "N/A"),
        "Reply-To": raw.get("reply-to", ["N/A"]),
        "Return-Path": raw.get("return-path", ["N/A"]),
        "X-Mailer": raw.get("x-mailer", ["N/A"]),
        "X-Priority": raw.get("x-priority", ["N/A"]),
        "X-Originating-IP": raw.get("x-originating-ip", ["N/A"]),
        "Message-ID": raw.get("message-id", ["N/A"]),
    }


def extract_ips_and_servers(parsed):
    header = parsed.get("header", {})
    received_entries = header.get("received", [])
    received_ips = header.get("received_ip", [])
    originating_ip = header.get("header", {}).get("x-originating-ip", [""])[0].strip("[]")
    sender_ip = header.get("header", {}).get("x-sender-ip", [""])[0]

    relay_servers = []
    for r in received_entries:
        if isinstance(r, dict):
            src = r.get("src", "")
            if "from" in src:
                parts = src.split()
                if len(parts) > 1:
                    relay_servers.append(parts[1])

    last_relay_ip = received_ips[-2] if len(received_ips) > 1 else "Unknown"
    last_relay_server = relay_servers[-2] if len(relay_servers) > 1 else "Unknown"
    source_ip = originating_ip or sender_ip or (received_ips[-1] if received_ips else "Unknown")

    return {
        "source_ip": source_ip,
        "last_relay_ip": last_relay_ip,
        "last_relay_server": last_relay_server,
        "all_ips": received_ips,
        "all_servers": relay_servers,
    }


def extract_auth_results(parsed):
    header_fields = parsed.get("header", {}).get("header", {})
    auth_field = header_fields.get("authentication-results", ["N/A"])[0]
    return {
        "SPF": header_fields.get("received-spf", ["N/A"])[0],
        "DKIM": auth_field,
        "DMARC": auth_field,
    }


def vt_lookup_sha256(sha256, verbose=False):
    if not VT_API_KEY or sha256 == "N/A":
        return {}

    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            permalink = f"https://www.virustotal.com/gui/file/{sha256}"
            if verbose:
                print(f"[✓] VT: {sha256} → {stats['malicious']} malicious | {permalink}")
            return {
                "VT_Malicious": stats.get("malicious", 0),
                "VT_Suspicious": stats.get("suspicious", 0),
                "VT_Undetected": stats.get("undetected", 0),
                "VT_Link": permalink,
            }
        else:
            return {"VT_Error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"VT_Error": str(e)}


def extract_attachments(parsed, vt_enabled=False, verbose=False):
    attachments = parsed.get("attachment", [])
    output = []
    for att in attachments:
        hash_data = att.get("hash", {})
        sha256 = hash_data.get("sha256", "N/A")
        vt = vt_lookup_sha256(sha256, verbose=verbose) if vt_enabled else {}

        output.append(
            {
                "filename": att.get("filename", "unknown"),
                "size": att.get("size", 0),
                "extension": att.get("extension", "unknown"),
                "content_type": att.get("content_header", {}).get("content-type", ["unknown"])[0],
                "hashes": {
                    "md5": hash_data.get("md5", "N/A"),
                    "sha1": hash_data.get("sha1", "N/A"),
                    "sha256": sha256,
                    "sha512": hash_data.get("sha512", "N/A"),
                },
                "VirusTotal": vt,
            }
        )
    return output


def extract_body(parsed):
    """Extract full body content metadata including URI/email/domain hashes"""
    bodies = parsed.get("body", [])
    body_summary = []

    for b in bodies:
        # Safely extract decoded content
        body_preview = b.get("content") or b.get("body") or ""
        if isinstance(body_preview, bytes):
            body_preview = body_preview.decode(errors="ignore")

        body_preview = body_preview.strip()[:500]

        body_summary.append(
            {
                "content_type": b.get("content_type", "N/A"),
                "hash": b.get("hash", "N/A"),
                "uri_hashes": b.get("uri_hash", []),
                "email_hashes": b.get("email_hash", []),
                "domain_hashes": b.get("domain_hash", []),
                "body_text": body_preview,
            }
        )

    return body_summary


def build_summary(parsed, file_path, vt_enabled=False, verbose=False):
    headers = extract_basic_headers(parsed)
    ips = extract_ips_and_servers(parsed)
    auth = extract_auth_results(parsed)
    attachments = extract_attachments(parsed, vt_enabled, verbose)
    body_content = extract_body(parsed)

    return {
        "File": file_path,
        "Headers": headers,
        "Source IP (likely attacker)": ips["source_ip"],
        "Mail Server that Relayed to Victim": {
            "IP": ips["last_relay_ip"],
            "Server": ips["last_relay_server"],
        },
        "All Relay IPs": ips["all_ips"],
        "All Relay Servers": ips["all_servers"],
        "SPF/DKIM/DMARC Results": auth,
        "Potentially Phishing Domains Found in URLs": [],
        "Attachments": attachments,
        "Body Content": body_content,
    }


def parse_args():
    parser = argparse.ArgumentParser(
        description="EML Parser — Extract metadata, attachments, relay info, and optional VirusTotal verdicts."
    )

    parser.add_argument("eml", help="Path to the .eml file to analyze")

    parser.add_argument("--output", "-o", help="Path to output JSON report file (e.g. report.json)")

    parser.add_argument(
        "--vt", action="store_true", help="Enable VirusTotal scan for SHA256 of attachments"
    )

    parser.add_argument(
        "--verbose", action="store_true", help="Enable verbose output (e.g. VT status per hash)"
    )

    return parser.parse_args()


def main():
    args = parse_args()
    eml_path = os.path.expanduser(args.eml)

    if not os.path.exists(eml_path):
        print(f"[INFO] File not found: {eml_path}")
        sys.exit(1)

    if args.vt and not VT_API_KEY:
        print("[INFO] VirusTotal lookup requested but VT_API_KEY not found in .env")
        sys.exit(1)

    try:
        parsed = parse_eml(eml_path)
        summary = build_summary(parsed, eml_path, vt_enabled=args.vt, verbose=args.verbose)

        print("\nEmail Threat Summary:\n")
        print(json.dumps(summary, indent=2, default=json_serial))

        if args.output:
            with open(args.output, "w") as f:
                json.dump(summary, f, indent=2, default=json_serial)
            print(f"\n[INFO] Output written to {args.output}")

    except Exception as e:
        print(f"[ERROR] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
