"""
vlair AI Reporter — Generate formatted investigation reports from AI analysis results.
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class AIReporter:
    """Generate formatted investigation reports from vlair analysis + AI assessment data."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def to_markdown(
        self,
        ioc_value: str,
        ioc_type: str,
        tool_result: dict,
        ai_result: dict,
        date: Optional[str] = None,
    ) -> str:
        """
        Generate a complete Markdown investigation report.

        Args:
            ioc_value:   The indicator that was analyzed (hash, domain, URL, …).
            ioc_type:    Analysis category (hash, domain, ip, url, email, …).
            tool_result: Raw result dict from a vlair tool.
            ai_result:   Structured result dict from ThreatSummarizer.summarize().
            date:        ISO date string (defaults to UTC now).

        Returns:
            Multi-line Markdown string ready to save as a .md file.
        """
        if date is None:
            date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        verdict = ai_result.get("verdict", "UNKNOWN")
        severity = ai_result.get("severity", "INFO")
        confidence = ai_result.get("confidence", 0.0)
        conf_pct = f"{int(confidence * 100)}%"
        key_findings = ai_result.get("key_findings", [])
        threat_context = ai_result.get("threat_context", "")
        actions = ai_result.get("recommended_actions", [])
        mitre = ai_result.get("mitre_attack", [])
        confidence_notes = ai_result.get("confidence_notes", "")
        meta = ai_result.get("metadata", {})
        model = meta.get("model", "unknown")

        # Pull IOCs from tool result if present
        iocs_for_blocking = self._extract_iocs(tool_result)

        lines = [
            f"# Investigation Report: {ioc_value}",
            "",
            f"**Date:** {date}  ",
            f"**IOC:** `{ioc_value}` ({ioc_type})  ",
            f"**Analyst Tool:** vlair AI (model: {model})  ",
            "",
            "---",
            "",
            "## Verdict",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Verdict | **{verdict}** |",
            f"| Severity | {severity} |",
            f"| Confidence | {conf_pct} |",
            "",
        ]

        # Executive Summary
        lines += [
            "## Executive Summary",
            "",
            threat_context if threat_context else "_No summary available._",
            "",
        ]

        # Key Findings
        lines += ["## Key Findings", ""]
        if key_findings:
            for finding in key_findings:
                lines.append(f"- {finding}")
        else:
            lines.append("_No key findings reported._")
        lines.append("")

        # Recommended Actions
        lines += ["## Recommended Actions", ""]
        if actions:
            priority_order = ["immediate", "short_term", "long_term"]
            grouped: dict = {}
            for act in actions:
                prio = act.get("priority", "other")
                grouped.setdefault(prio, []).append(act.get("action", ""))

            for prio in priority_order + [p for p in grouped if p not in priority_order]:
                if prio not in grouped:
                    continue
                label = prio.replace("_", " ").title()
                lines.append(f"### {label}")
                for item in grouped[prio]:
                    lines.append(f"- {item}")
                lines.append("")
        else:
            lines.append("_No specific actions recommended._")
            lines.append("")

        # Technical Findings (raw tool data summary)
        lines += ["## Technical Findings", ""]
        risk_score = tool_result.get("risk_score")
        if risk_score is not None:
            lines.append(f"- **Risk Score:** {risk_score}/100")
        detections = tool_result.get("detections")
        total_engines = tool_result.get("total_engines")
        if detections is not None and total_engines is not None:
            lines.append(f"- **AV Detections:** {detections}/{total_engines}")
        malware_family = tool_result.get("malware_family") or tool_result.get(
            "suggested_threat_label"
        )
        if malware_family:
            lines.append(f"- **Malware Family:** {malware_family}")
        categories = tool_result.get("categories", [])
        if categories:
            lines.append(f"- **Categories:** {', '.join(categories[:5])}")
        lines.append("")

        # IOCs for Blocking
        lines += ["## IOCs for Blocking", ""]
        if iocs_for_blocking:
            for ioc_cat, ioc_list in iocs_for_blocking.items():
                if ioc_list:
                    lines.append(f"### {ioc_cat.replace('_', ' ').title()}")
                    for ioc in ioc_list[:20]:
                        lines.append(f"- `{ioc}`")
                    lines.append("")
        else:
            lines.append(f"- `{ioc_value}` ({ioc_type})")
            lines.append("")

        # MITRE ATT&CK
        lines += ["## MITRE ATT&CK Coverage", ""]
        if mitre:
            lines.append(", ".join(f"`{t}`" for t in mitre))
        else:
            lines.append("_No MITRE ATT&CK techniques identified._")
        lines.append("")

        # Confidence Notes
        if confidence_notes:
            lines += ["## Confidence Notes", "", confidence_notes, ""]

        # Footer
        lines += [
            "---",
            "",
            f"*Generated by vlair AI — {date}*",
        ]

        return "\n".join(lines)

    def to_jira(self, ioc_value: str, ioc_type: str, ai_result: dict) -> str:
        """
        Generate a Jira-formatted ticket description using Jira wiki markup.

        Returns a string ready to paste into a Jira ticket description field.
        """
        verdict = ai_result.get("verdict", "UNKNOWN")
        severity = ai_result.get("severity", "INFO")
        confidence = ai_result.get("confidence", 0.0)
        conf_pct = f"{int(confidence * 100)}%"
        findings = ai_result.get("key_findings", [])
        context = ai_result.get("threat_context", "")
        actions = ai_result.get("recommended_actions", [])
        mitre = ai_result.get("mitre_attack", [])
        date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        lines = [
            f"h2. Security Investigation: {ioc_value}",
            "",
            f"*Date:* {date}",
            f"*IOC:* {{code}}{ioc_value}{{code}} ({ioc_type})",
            f"*Verdict:* *{verdict}* (confidence: {conf_pct})",
            f"*Severity:* {severity}",
            "",
            "h3. Executive Summary",
            context if context else "_No summary available._",
            "",
            "h3. Key Findings",
        ]
        for f in findings:
            lines.append(f"* {f}")
        lines.append("")

        lines.append("h3. Recommended Actions")
        priority_order = ["immediate", "short_term", "long_term"]
        grouped: dict = {}
        for act in actions:
            prio = act.get("priority", "other")
            grouped.setdefault(prio, []).append(act.get("action", ""))
        for prio in priority_order + [p for p in grouped if p not in priority_order]:
            if prio not in grouped:
                continue
            label = prio.replace("_", " ").upper()
            lines.append(f"*{label}:*")
            for item in grouped[prio]:
                lines.append(f"** {item}")
        lines.append("")

        if mitre:
            lines.append(f"h3. MITRE ATT&CK: {', '.join(mitre)}")
            lines.append("")

        lines.append("----")
        lines.append(f"_Generated by vlair AI — {date}_")

        return "\n".join(lines)

    def save(self, content: str, format: str, output_path: Optional[str] = None) -> str:
        """
        Save report content to a file.

        Args:
            content:     The report string to write.
            format:      File format hint used for extension ("markdown" / "md" / "jira" / "txt").
            output_path: Explicit file path; if None, a timestamped file is created in cwd.

        Returns:
            Absolute path of the saved file.
        """
        if output_path:
            path = Path(output_path)
        else:
            ext_map = {"markdown": "md", "md": "md", "jira": "txt", "txt": "txt"}
            ext = ext_map.get(format, "md")
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = Path(f"vlair_report_{ts}.{ext}")

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return str(path.resolve())

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _extract_iocs(self, tool_result: dict) -> dict:
        """Extract IOC lists from a tool result for the blocking section."""
        iocs: dict = {}

        # Direct IOC fields
        for field in ("ips", "ip_addresses", "domains", "urls", "hashes", "emails"):
            val = tool_result.get(field, [])
            if isinstance(val, list) and val:
                iocs[field] = val

        # Nested under 'iocs' key (IOC extractor output)
        nested = tool_result.get("iocs", {})
        if isinstance(nested, dict):
            for key, val in nested.items():
                if isinstance(val, list) and val:
                    iocs.setdefault(key, val)

        # DNS section
        dns = tool_result.get("dns", {})
        if isinstance(dns, dict):
            a_recs = dns.get("a_records", [])
            if a_recs:
                iocs.setdefault("ip_addresses", a_recs)

        return iocs
