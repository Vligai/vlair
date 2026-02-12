"""
Analysis Prompt Templates

Templates for constructing analysis prompts from threat intelligence data.
"""

from typing import Dict, Any, Optional
import json

ANALYSIS_PROMPT_TEMPLATE = """
Analyze the following threat intelligence data and provide a security assessment.

INPUT TYPE: {input_type}
INPUT VALUE: {input_value}

THREAT INTELLIGENCE DATA:
{threat_intel_json}

BEHAVIORAL ANALYSIS (if available):
{behavioral_data}

ORGANIZATION CONTEXT (if available):
Industry: {org_industry}
Size: {org_size}
Critical Assets: {critical_assets}

Provide your assessment following the standard output format.
"""

QUICK_ANALYSIS_TEMPLATE = """
Provide a brief security assessment of the following indicator:

TYPE: {input_type}
VALUE: {input_value}

KEY DATA:
{summary_data}

Give a quick verdict (MALICIOUS/SUSPICIOUS/CLEAN), confidence level, and 2-3 key findings.
"""

THOROUGH_ANALYSIS_TEMPLATE = """
Perform a comprehensive security analysis of the following indicator.

INPUT TYPE: {input_type}
INPUT VALUE: {input_value}

COMPLETE THREAT INTELLIGENCE DATA:
{threat_intel_json}

BEHAVIORAL INDICATORS:
{behavioral_data}

RELATED IOCS:
{related_iocs}

HISTORICAL CONTEXT:
{historical_data}

ORGANIZATION PROFILE:
Industry: {org_industry}
Organization Size: {org_size}
Critical Assets: {critical_assets}
Geographic Region: {org_region}

Provide a comprehensive assessment including:
1. Detailed verdict with confidence breakdown
2. Complete threat context and actor attribution
3. Full attack chain analysis
4. Comprehensive recommended actions with SIEM queries
5. Risk assessment specific to the organization profile
6. IOCs for blocking with context
"""


def build_analysis_prompt(
    input_type: str,
    input_value: str,
    threat_intel: Dict[str, Any],
    depth: str = "standard",
    behavioral_data: Optional[Dict[str, Any]] = None,
    org_context: Optional[Dict[str, str]] = None,
    related_iocs: Optional[Dict[str, Any]] = None,
    historical_data: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Build an analysis prompt from threat intelligence data.

    Args:
        input_type: Type of input (hash, domain, ip, url, email)
        input_value: The actual IOC value
        threat_intel: Aggregated threat intelligence data
        depth: Analysis depth (quick, standard, thorough)
        behavioral_data: Optional sandbox/behavioral analysis data
        org_context: Optional organization context
        related_iocs: Optional related IOCs for correlation
        historical_data: Optional historical context

    Returns:
        Formatted prompt string
    """
    # Select template based on depth
    if depth == "quick":
        template = QUICK_ANALYSIS_TEMPLATE
        return template.format(
            input_type=input_type,
            input_value=input_value,
            summary_data=_summarize_threat_intel(threat_intel),
        )

    elif depth == "thorough":
        template = THOROUGH_ANALYSIS_TEMPLATE
        org = org_context or {}
        return template.format(
            input_type=input_type,
            input_value=input_value,
            threat_intel_json=json.dumps(threat_intel, indent=2),
            behavioral_data=(
                json.dumps(behavioral_data, indent=2) if behavioral_data else "Not available"
            ),
            related_iocs=json.dumps(related_iocs, indent=2) if related_iocs else "Not available",
            historical_data=(
                json.dumps(historical_data, indent=2) if historical_data else "Not available"
            ),
            org_industry=org.get("industry", "Not specified"),
            org_size=org.get("size", "Not specified"),
            critical_assets=org.get("critical_assets", "Not specified"),
            org_region=org.get("region", "Not specified"),
        )

    else:  # standard
        template = ANALYSIS_PROMPT_TEMPLATE
        org = org_context or {}
        return template.format(
            input_type=input_type,
            input_value=input_value,
            threat_intel_json=json.dumps(threat_intel, indent=2),
            behavioral_data=(
                json.dumps(behavioral_data, indent=2) if behavioral_data else "Not available"
            ),
            org_industry=org.get("industry", "Not specified"),
            org_size=org.get("size", "Not specified"),
            critical_assets=org.get("critical_assets", "Not specified"),
        )


def _summarize_threat_intel(threat_intel: Dict[str, Any]) -> str:
    """
    Create a brief summary of threat intel for quick analysis.

    Args:
        threat_intel: Full threat intelligence data

    Returns:
        Summarized string
    """
    summary_lines = []

    # VirusTotal summary
    if "virustotal" in threat_intel:
        vt = threat_intel["virustotal"]
        if "detection_ratio" in vt:
            summary_lines.append(f"VirusTotal: {vt['detection_ratio']}")
        if "malware_families" in vt:
            summary_lines.append(f"Families: {', '.join(vt['malware_families'][:3])}")

    # MalwareBazaar summary
    if "malwarebazaar" in threat_intel:
        mb = threat_intel["malwarebazaar"]
        if "signature" in mb:
            summary_lines.append(f"MalwareBazaar: {mb['signature']}")
        if "first_seen" in mb:
            summary_lines.append(f"First seen: {mb['first_seen']}")

    # AbuseIPDB summary
    if "abuseipdb" in threat_intel:
        abuse = threat_intel["abuseipdb"]
        if "abuse_confidence_score" in abuse:
            summary_lines.append(f"AbuseIPDB score: {abuse['abuse_confidence_score']}%")

    # Risk score if present
    if "risk_score" in threat_intel:
        summary_lines.append(f"Risk score: {threat_intel['risk_score']}/100")

    if not summary_lines:
        summary_lines.append("No significant threat intelligence found")

    return "\n".join(summary_lines)


def build_correlation_prompt(
    iocs: list,
    threat_intel_results: Dict[str, Dict[str, Any]],
    org_context: Optional[Dict[str, str]] = None,
) -> str:
    """
    Build a correlation analysis prompt for multiple IOCs.

    Args:
        iocs: List of IOC dictionaries with type and value
        threat_intel_results: Dict mapping IOC values to their threat intel
        org_context: Optional organization context

    Returns:
        Formatted correlation prompt
    """
    org = org_context or {}

    iocs_formatted = "\n".join([f"- {ioc['type']}: {ioc['value']}" for ioc in iocs])

    return f"""
Perform a correlation analysis of the following indicators of compromise.

INDICATORS:
{iocs_formatted}

INDIVIDUAL THREAT INTELLIGENCE:
{json.dumps(threat_intel_results, indent=2)}

ORGANIZATION CONTEXT:
Industry: {org.get('industry', 'Not specified')}
Size: {org.get('size', 'Not specified')}

Analyze relationships between these IOCs and provide:
1. Campaign identification (if applicable)
2. Threat actor attribution (if possible)
3. Attack chain reconstruction
4. Unified severity assessment
5. Consolidated recommended actions
6. Complete IOC list for blocking
"""
