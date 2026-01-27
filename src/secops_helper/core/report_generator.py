#!/usr/bin/env python3
"""
Report Generator - Generate HTML and Markdown analysis reports
Part of SecOps Helper Operationalization (Phase 5)
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from html import escape as html_escape

from .scorer import RiskScorer, Severity, Verdict


@dataclass
class ReportData:
    """Structured data for report generation"""

    input_value: str
    input_type: str
    timestamp: str
    risk_score: int
    verdict: str
    confidence: str
    findings: List[Dict[str, Any]]
    finding_counts: Dict[str, int]
    iocs: Dict[str, List[str]]
    recommendations: List[str]
    tool_results: Dict[str, Any]
    tools_executed: List[str]
    workflow_name: Optional[str] = None
    steps_completed: Optional[int] = None
    steps_total: Optional[int] = None
    step_results: Optional[List[Dict]] = None
    duration_seconds: Optional[float] = None


class ReportGenerator:
    """
    Generate professional HTML and Markdown reports from analysis results.
    Reports are self-contained with no external dependencies.
    """

    SUPPORTED_FORMATS = ["html", "markdown", "md"]

    def generate(
        self, result: Dict[str, Any], report_format: str = "html", output_path: Optional[str] = None
    ) -> str:
        """
        Generate a report file from analysis results.

        Args:
            result: Analysis result dict from Analyzer or Workflow
            report_format: 'html', 'markdown', or 'md'
            output_path: File path for report (auto-generated if None)

        Returns:
            Path to generated report file
        """
        if report_format not in self.SUPPORTED_FORMATS:
            raise ValueError(
                f"Unsupported format: {report_format}. " f"Use: {', '.join(self.SUPPORTED_FORMATS)}"
            )

        report_data = self._build_report_data(result)

        if report_format == "html":
            content = self.format_html(report_data)
            ext = ".html"
        else:
            content = self.format_markdown(report_data)
            ext = ".md"

        if not output_path:
            output_path = self._generate_filename(report_data, ext)

        Path(output_path).write_text(content, encoding="utf-8")
        return output_path

    def _build_report_data(self, result: Dict[str, Any]) -> ReportData:
        """Convert raw result dict to structured ReportData."""
        scorer = result.get("scorer")
        if isinstance(scorer, RiskScorer):
            summary = scorer.get_summary()
            findings = scorer.get_findings()
            recommendations = scorer.get_recommendations()
        else:
            summary = result.get("summary", {})
            findings = result.get("findings", [])
            recommendations = result.get("recommendations", [])

        return ReportData(
            input_value=result.get("input", "Unknown"),
            input_type=str(result.get("type", "unknown")),
            timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            risk_score=summary.get("risk_score", 0),
            verdict=summary.get("verdict", "UNKNOWN"),
            confidence=summary.get("confidence", "low"),
            findings=findings,
            finding_counts=summary.get("finding_counts", {}),
            iocs=result.get("iocs", {}),
            recommendations=recommendations,
            tool_results=result.get("tool_results", {}),
            tools_executed=list(result.get("tool_results", {}).keys()),
            workflow_name=result.get("workflow"),
            steps_completed=result.get("steps_completed"),
            steps_total=result.get("steps_total"),
            step_results=result.get("step_results"),
            duration_seconds=result.get("duration_seconds"),
        )

    def _generate_filename(self, data: ReportData, ext: str) -> str:
        """Generate a descriptive filename for the report."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        input_type = data.input_type.replace(" ", "_")
        return f"secops_report_{input_type}_{timestamp}{ext}"

    def _defang(self, value: str) -> str:
        """Defang IOCs for safe display in reports."""
        value = value.replace("http://", "hxxp://")
        value = value.replace("https://", "hxxps://")
        value = value.replace(".", "[.]")
        return value

    def _verdict_description(self, verdict: str) -> str:
        """Get a description for the verdict."""
        descriptions = {
            "MALICIOUS": "This artifact is assessed as malicious with high confidence.",
            "SUSPICIOUS": "This artifact exhibits suspicious behavior and warrants further investigation.",
            "LOW_RISK": "This artifact shows minor indicators but is likely benign.",
            "CLEAN": "No malicious indicators were detected.",
            "UNKNOWN": "Insufficient data to make a determination.",
        }
        return descriptions.get(verdict, "Verdict could not be determined.")

    def _generate_executive_summary(self, data: ReportData) -> str:
        """Generate a natural-language executive summary paragraph."""
        parts = []

        parts.append(f"Analysis of the provided {data.input_type} input")
        if data.input_value and data.input_value != "Unknown":
            parts.append(f'("{data.input_value}")')

        parts.append(f"resulted in a verdict of {data.verdict}")
        parts.append(f"with a risk score of {data.risk_score}/100.")

        total = len(data.findings)
        if total > 0:
            critical = data.finding_counts.get("critical", 0)
            high = data.finding_counts.get("high", 0)
            if critical > 0:
                parts.append(f"{critical} critical finding{'s' if critical != 1 else ''}")
                if high > 0:
                    parts.append(f"and {high} high-severity finding{'s' if high != 1 else ''}")
                parts.append(f"{'were' if critical + high > 1 else 'was'} identified.")
            elif high > 0:
                parts.append(f"{high} high-severity finding{'s' if high != 1 else ''}")
                parts.append(f"{'were' if high > 1 else 'was'} identified.")
            else:
                parts.append(f"{total} finding{'s' if total != 1 else ''}")
                parts.append(f"of lower severity {'were' if total > 1 else 'was'} identified.")

            if data.findings:
                top = data.findings[0]
                parts.append(f"The most significant finding: {top.get('message', '')}.")
        else:
            parts.append("No significant findings were identified during the analysis.")

        ioc_count = sum(len(v) for v in data.iocs.values() if isinstance(v, list))
        if ioc_count > 0:
            parts.append(
                f"A total of {ioc_count} indicator{'s' if ioc_count != 1 else ''} of compromise"
            )
            parts.append(f"{'were' if ioc_count != 1 else 'was'} extracted.")

        if data.workflow_name:
            parts.append(f"This analysis was performed using the {data.workflow_name} workflow.")

        return " ".join(parts)

    def _score_class(self, score: int) -> str:
        """Get CSS class for score level."""
        if score >= 70:
            return "high"
        elif score >= 40:
            return "medium"
        return "low"

    # ─── HTML Generation ─────────────────────────────────────────────────

    def format_html(self, data: ReportData) -> str:
        """Generate a self-contained HTML report with inline CSS."""
        verdict_lower = data.verdict.lower()
        score_class = self._score_class(data.risk_score)
        executive_summary = self._generate_executive_summary(data)

        findings_html = self._html_findings_section(data.findings)
        ioc_html = self._html_ioc_table(data.iocs)
        recommendations_html = self._html_recommendations(data.recommendations)
        timeline_html = self._html_timeline(data)
        metadata_html = self._html_metadata(data)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecOps Helper Analysis Report - {html_escape(data.input_value)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               line-height: 1.6; color: #333; max-width: 900px; margin: 0 auto; padding: 20px;
               background: #fafafa; }}
        .report-header {{ background: #1a1a2e; color: #fff; padding: 30px; border-radius: 8px 8px 0 0; }}
        .report-header h1 {{ font-size: 24px; margin-bottom: 5px; }}
        .report-header .meta {{ color: #aaa; font-size: 14px; }}
        .verdict-box {{ padding: 20px; border-radius: 0 0 8px 8px; margin-bottom: 25px; }}
        .verdict-malicious {{ background: #fee; border-left: 4px solid #dc3545; }}
        .verdict-suspicious {{ background: #fff3cd; border-left: 4px solid #ffc107; }}
        .verdict-low_risk {{ background: #d4edda; border-left: 4px solid #28a745; }}
        .verdict-clean {{ background: #d4edda; border-left: 4px solid #28a745; }}
        .verdict-unknown {{ background: #e2e3e5; border-left: 4px solid #6c757d; }}
        .verdict-box h2 {{ margin-bottom: 8px; }}
        .score-container {{ margin-top: 10px; }}
        .score-bar {{ width: 200px; height: 20px; background: #e9ecef; border-radius: 10px;
                     overflow: hidden; display: inline-block; vertical-align: middle; }}
        .score-fill {{ height: 100%; border-radius: 10px; }}
        .score-high {{ background: #dc3545; }}
        .score-medium {{ background: #ffc107; }}
        .score-low {{ background: #28a745; }}
        .section {{ background: #fff; padding: 20px; margin-bottom: 20px; border-radius: 8px;
                   box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .section h2 {{ font-size: 18px; color: #1a1a2e; border-bottom: 2px solid #eee;
                      padding-bottom: 8px; margin-bottom: 15px; }}
        .finding {{ padding: 10px 15px; margin-bottom: 8px; border-radius: 4px; border-left: 3px solid; }}
        .finding-critical {{ background: #fee; border-color: #dc3545; }}
        .finding-high {{ background: #fff3cd; border-color: #fd7e14; }}
        .finding-medium {{ background: #e8f4fd; border-color: #17a2b8; }}
        .finding-low {{ background: #f8f9fa; border-color: #6c757d; }}
        .finding-info {{ background: #f8f9fa; border-color: #adb5bd; }}
        .badge {{ display: inline-block; padding: 2px 8px; font-size: 11px; font-weight: bold;
                 border-radius: 3px; color: #fff; margin-right: 8px; text-transform: uppercase; }}
        .badge-critical {{ background: #dc3545; }}
        .badge-high {{ background: #fd7e14; }}
        .badge-medium {{ background: #17a2b8; }}
        .badge-low {{ background: #6c757d; }}
        .badge-info {{ background: #adb5bd; }}
        .ioc-table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
        .ioc-table th {{ background: #f8f9fa; text-align: left; padding: 10px;
                        border-bottom: 2px solid #dee2e6; }}
        .ioc-table td {{ padding: 8px 10px; border-bottom: 1px solid #eee;
                        font-family: 'Consolas', 'Monaco', monospace; word-break: break-all; }}
        .timeline-item {{ padding: 10px 0 10px 20px; border-left: 2px solid #dee2e6;
                         margin-left: 10px; position: relative; }}
        .timeline-item::before {{ content: ''; width: 10px; height: 10px; border-radius: 50%;
                                 position: absolute; left: -6px; top: 14px; }}
        .timeline-success::before {{ background: #28a745; }}
        .timeline-failed::before {{ background: #dc3545; }}
        .timeline-neutral::before {{ background: #17a2b8; }}
        .recommendations ol {{ padding-left: 20px; }}
        .recommendations li {{ margin-bottom: 8px; }}
        .report-footer {{ margin-top: 30px; padding-top: 15px; border-top: 1px solid #eee;
                         color: #999; font-size: 12px; text-align: center; }}
        .empty-note {{ color: #999; font-style: italic; }}
        @media (max-width: 600px) {{ body {{ padding: 10px; }} .report-header {{ padding: 15px; }} }}
    </style>
</head>
<body>
    <div class="report-header">
        <h1>SecOps Helper - Analysis Report</h1>
        <div class="meta">Generated: {html_escape(data.timestamp)} | Type: {html_escape(data.input_type)}</div>
    </div>

    <div class="verdict-box verdict-{verdict_lower}">
        <h2>Verdict: {html_escape(data.verdict)}</h2>
        <p>{html_escape(self._verdict_description(data.verdict))}</p>
        <div class="score-container">
            Risk Score: <strong>{data.risk_score}/100</strong>
            <div class="score-bar"><div class="score-fill score-{score_class}" style="width:{data.risk_score}%"></div></div>
            &nbsp; Confidence: {html_escape(data.confidence)}
        </div>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <p>{html_escape(executive_summary)}</p>
    </div>

    <div class="section">
        <h2>Findings ({len(data.findings)})</h2>
        {findings_html}
    </div>

    <div class="section">
        <h2>Indicators of Compromise</h2>
        {ioc_html}
    </div>

    <div class="section recommendations">
        <h2>Recommended Actions</h2>
        {recommendations_html}
    </div>

    <div class="section">
        <h2>Analysis Timeline</h2>
        {timeline_html}
    </div>

    <div class="section">
        <h2>Analysis Metadata</h2>
        {metadata_html}
    </div>

    <div class="report-footer">
        <p>Generated by SecOps Helper v4.0.0 | Operationalization Phase 5</p>
        <p>All IOCs are defanged for safe display. Re-fang before use in detection rules.</p>
    </div>
</body>
</html>"""

    def _html_findings_section(self, findings: List[Dict]) -> str:
        """Build HTML for findings grouped by severity."""
        if not findings:
            return '<p class="empty-note">No findings to report.</p>'

        lines = []
        for finding in findings:
            severity = finding.get("severity", "info")
            message = finding.get("message", "")
            source = finding.get("source", "")
            lines.append(
                f'<div class="finding finding-{html_escape(severity)}">'
                f'<span class="badge badge-{html_escape(severity)}">{html_escape(severity)}</span>'
                f"{html_escape(message)}"
                f'<span style="color:#999; font-size:12px; margin-left:10px;">({html_escape(source)})</span>'
                f"</div>"
            )
        return "\n        ".join(lines)

    def _html_ioc_table(self, iocs: Dict[str, List[str]]) -> str:
        """Build HTML for IOC table with defanged values."""
        has_iocs = any(v for v in iocs.values() if isinstance(v, list) and len(v) > 0)
        if not has_iocs:
            return '<p class="empty-note">No indicators of compromise extracted.</p>'

        rows = []
        for ioc_type, values in iocs.items():
            if not isinstance(values, list) or not values:
                continue
            type_label = ioc_type.replace("_", " ").capitalize()
            for value in values:
                defanged = self._defang(str(value))
                rows.append(
                    f"<tr><td>{html_escape(type_label)}</td>"
                    f"<td>{html_escape(defanged)}</td></tr>"
                )

        return (
            '<table class="ioc-table">'
            "<tr><th>Type</th><th>Value (Defanged)</th></tr>" + "".join(rows) + "</table>"
        )

    def _html_recommendations(self, recommendations: List[str]) -> str:
        """Build HTML for recommendations list."""
        if not recommendations:
            return '<p class="empty-note">No specific actions required.</p>'

        items = "".join(f"<li>{html_escape(r)}</li>" for r in recommendations)
        return f"<ol>{items}</ol>"

    def _html_timeline(self, data: ReportData) -> str:
        """Build HTML for analysis timeline."""
        if data.step_results:
            lines = []
            for step in data.step_results:
                name = step.get("name", step.get("step_name", "Unknown"))
                success = step.get("success", True)
                duration = step.get("duration_ms", 0)
                css_class = "timeline-success" if success else "timeline-failed"
                status = "Success" if success else "Failed"
                error = step.get("error", "")
                detail = f" - {html_escape(error)}" if error else ""
                lines.append(
                    f'<div class="timeline-item {css_class}">'
                    f"<strong>{html_escape(name)}</strong> - {status} ({duration}ms){detail}"
                    f"</div>"
                )
            if data.duration_seconds is not None:
                lines.append(
                    f'<p style="margin-top:10px; color:#666;">Total duration: {data.duration_seconds:.1f}s</p>'
                )
            return "\n        ".join(lines)

        if data.tools_executed:
            lines = []
            for tool in data.tools_executed:
                lines.append(
                    f'<div class="timeline-item timeline-neutral">'
                    f"<strong>{html_escape(tool)}</strong> - Executed"
                    f"</div>"
                )
            return "\n        ".join(lines)

        return '<p class="empty-note">No timeline data available.</p>'

    def _html_metadata(self, data: ReportData) -> str:
        """Build HTML metadata table."""
        tools_list = ", ".join(data.tools_executed) if data.tools_executed else "N/A"
        workflow = data.workflow_name or "N/A (direct analysis)"
        duration = f"{data.duration_seconds:.1f}s" if data.duration_seconds else "N/A"
        steps = (
            f"{data.steps_completed}/{data.steps_total}"
            if data.steps_completed is not None
            else "N/A"
        )

        return (
            '<table class="ioc-table">'
            "<tr><th>Field</th><th>Value</th></tr>"
            f"<tr><td>Input</td><td>{html_escape(data.input_value)}</td></tr>"
            f"<tr><td>Type</td><td>{html_escape(data.input_type)}</td></tr>"
            f"<tr><td>Timestamp</td><td>{html_escape(data.timestamp)}</td></tr>"
            f"<tr><td>Tools Executed</td><td>{html_escape(tools_list)}</td></tr>"
            f"<tr><td>Workflow</td><td>{html_escape(workflow)}</td></tr>"
            f"<tr><td>Steps</td><td>{html_escape(steps)}</td></tr>"
            f"<tr><td>Duration</td><td>{html_escape(duration)}</td></tr>"
            "</table>"
        )

    # ─── Markdown Generation ─────────────────────────────────────────────

    def format_markdown(self, data: ReportData) -> str:
        """Generate a clean Markdown report."""
        executive_summary = self._generate_executive_summary(data)
        findings_md = self._md_findings_section(data.findings, data.finding_counts)
        ioc_md = self._md_ioc_table(data.iocs)
        recommendations_md = self._md_recommendations(data.recommendations)
        timeline_md = self._md_timeline(data)
        metadata_md = self._md_metadata(data)

        return f"""# SecOps Helper - Analysis Report

**Generated:** {data.timestamp}
**Input:** `{data.input_value}`
**Type:** {data.input_type}

---

## Verdict: {data.verdict}

| Metric | Value |
|--------|-------|
| Risk Score | {data.risk_score}/100 |
| Verdict | {data.verdict} |
| Confidence | {data.confidence} |

{self._verdict_description(data.verdict)}

---

## Executive Summary

{executive_summary}

---

{findings_md}

---

{ioc_md}

---

{recommendations_md}

---

{timeline_md}

---

{metadata_md}

---

*Generated by SecOps Helper v4.0.0 | All IOCs are defanged for safe display.*
"""

    def _md_findings_section(self, findings: List[Dict], finding_counts: Dict[str, int]) -> str:
        """Build Markdown findings section grouped by severity."""
        total = len(findings)
        lines = [f"## Findings ({total})"]

        if not findings:
            lines.append("\nNo findings to report.")
            return "\n".join(lines)

        severity_order = ["critical", "high", "medium", "low", "info"]
        grouped = {}
        for f in findings:
            sev = f.get("severity", "info")
            grouped.setdefault(sev, []).append(f)

        for sev in severity_order:
            items = grouped.get(sev, [])
            if not items:
                continue
            count = len(items)
            lines.append(f"\n### {sev.capitalize()} ({count})\n")
            for item in items:
                msg = item.get("message", "")
                source = item.get("source", "")
                lines.append(f"- **[{sev.upper()}]** {msg} *(source: {source})*")

        return "\n".join(lines)

    def _md_ioc_table(self, iocs: Dict[str, List[str]]) -> str:
        """Build Markdown IOC table."""
        lines = ["## Indicators of Compromise"]

        has_iocs = any(v for v in iocs.values() if isinstance(v, list) and len(v) > 0)
        if not has_iocs:
            lines.append("\nNo indicators of compromise extracted.")
            return "\n".join(lines)

        lines.append("")
        lines.append("| Type | Value |")
        lines.append("|------|-------|")

        for ioc_type, values in iocs.items():
            if not isinstance(values, list) or not values:
                continue
            type_label = ioc_type.replace("_", " ").capitalize()
            for value in values:
                defanged = self._defang(str(value))
                lines.append(f"| {type_label} | `{defanged}` |")

        lines.append("")
        lines.append("> All IOCs are defanged for safe display.")

        return "\n".join(lines)

    def _md_recommendations(self, recommendations: List[str]) -> str:
        """Build Markdown recommendations section."""
        lines = ["## Recommended Actions"]

        if not recommendations:
            lines.append("\nNo specific actions required.")
            return "\n".join(lines)

        lines.append("")
        for i, rec in enumerate(recommendations, 1):
            lines.append(f"{i}. {rec}")

        return "\n".join(lines)

    def _md_timeline(self, data: ReportData) -> str:
        """Build Markdown timeline section."""
        lines = ["## Analysis Timeline"]

        if data.step_results:
            lines.append("")
            lines.append("| Step | Status | Duration |")
            lines.append("|------|--------|----------|")
            for step in data.step_results:
                name = step.get("name", step.get("step_name", "Unknown"))
                success = step.get("success", True)
                duration = step.get("duration_ms", 0)
                status = "Success" if success else "Failed"
                lines.append(f"| {name} | {status} | {duration}ms |")
            if data.duration_seconds is not None:
                lines.append(f"\n*Total duration: {data.duration_seconds:.1f}s*")
        elif data.tools_executed:
            lines.append("")
            lines.append("| Tool | Status |")
            lines.append("|------|--------|")
            for tool in data.tools_executed:
                lines.append(f"| {tool} | Executed |")
        else:
            lines.append("\nNo timeline data available.")

        return "\n".join(lines)

    def _md_metadata(self, data: ReportData) -> str:
        """Build Markdown metadata section."""
        tools_list = ", ".join(data.tools_executed) if data.tools_executed else "N/A"
        workflow = data.workflow_name or "N/A (direct analysis)"
        duration = f"{data.duration_seconds:.1f}s" if data.duration_seconds else "N/A"

        lines = ["## Metadata"]
        lines.append("")
        lines.append(f"- **Tool Version:** SecOps Helper v4.0.0")
        lines.append(f"- **Input:** `{data.input_value}`")
        lines.append(f"- **Type:** {data.input_type}")
        lines.append(f"- **Workflow:** {workflow}")
        lines.append(f"- **Tools Executed:** {tools_list}")
        lines.append(f"- **Duration:** {duration}")

        return "\n".join(lines)
