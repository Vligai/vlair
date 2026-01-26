#!/usr/bin/env python3
"""
Phishing Email Investigation Workflow
Comprehensive analysis of suspicious emails
"""

import sys
from pathlib import Path
from typing import Dict, Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.workflow import Workflow, WorkflowStep, StepResult, WorkflowContext, workflow
from core.scorer import Severity


@workflow
class PhishingEmailWorkflow(Workflow):
    """
    Phishing Email Investigation Workflow

    Steps:
    1. Parse email headers and validate authentication (SPF/DKIM/DMARC)
    2. Extract all IOCs from email body and headers
    3. Check attachment hashes against threat intelligence
    4. Check domains/IPs against reputation services
    5. Check URLs for malicious indicators
    6. Analyze certificates from URLs/sender domain
    7. Generate phishing probability score
    """

    @property
    def name(self) -> str:
        return "phishing-email"

    @property
    def description(self) -> str:
        return "Comprehensive phishing email investigation"

    def _define_steps(self):
        self.steps = [
            WorkflowStep(
                name="parse_email",
                description="Parse email headers and validate authentication",
                tool="eml_parser",
                required=True,
            ),
            WorkflowStep(
                name="extract_iocs",
                description="Extract IOCs from email",
                tool="ioc_extractor",
                required=True,
                depends_on=["parse_email"],
            ),
            WorkflowStep(
                name="check_hashes",
                description="Check attachment hashes against threat intel",
                tool="hash_lookup",
                required=False,
                depends_on=["parse_email"],
            ),
            WorkflowStep(
                name="check_domains",
                description="Check domains against reputation services",
                tool="domain_intel",
                required=False,
                depends_on=["extract_iocs"],
            ),
            WorkflowStep(
                name="check_urls",
                description="Analyze URLs for malicious indicators",
                tool="url_analyzer",
                required=False,
                depends_on=["extract_iocs"],
            ),
            WorkflowStep(
                name="check_certificates",
                description="Analyze certificates from sender/URLs",
                tool="cert_analyzer",
                required=False,
                depends_on=["extract_iocs"],
            ),
            WorkflowStep(
                name="calculate_score", description="Calculate phishing probability score", tool="scorer", required=True
            ),
        ]

    def _execute_step(self, step: WorkflowStep, context: WorkflowContext) -> StepResult:
        """Execute a single workflow step"""

        if step.name == "parse_email":
            return self._parse_email(context)
        elif step.name == "extract_iocs":
            return self._extract_iocs(context)
        elif step.name == "check_hashes":
            return self._check_hashes(context)
        elif step.name == "check_domains":
            return self._check_domains(context)
        elif step.name == "check_urls":
            return self._check_urls(context)
        elif step.name == "check_certificates":
            return self._check_certificates(context)
        elif step.name == "calculate_score":
            return self._calculate_score(context)
        else:
            return StepResult(step_name=step.name, success=False, error="Unknown step")

    def _parse_email(self, context: WorkflowContext) -> StepResult:
        """Parse email and validate authentication"""
        try:
            from emlAnalysis.emlParser import EMLParser

            parser = EMLParser(verbose=self.verbose)
            result = parser.parse(context.input_value)

            context.add_tool_result("eml_parser", result)
            context.data["email_parsed"] = result

            # Extract authentication results for scoring
            auth = result.get("authentication", {})

            # Check SPF
            spf = auth.get("spf", {})
            if spf.get("result") == "fail":
                context.scorer.add_finding(
                    Severity.HIGH, "SPF validation failed - sender may be spoofed", "eml_parser", {"spf": spf}
                )
            elif spf.get("result") == "softfail":
                context.scorer.add_finding(
                    Severity.MEDIUM, "SPF soft fail - sender authentication weak", "eml_parser", {"spf": spf}
                )

            # Check DKIM
            dkim = auth.get("dkim", {})
            if dkim.get("result") == "fail":
                context.scorer.add_finding(Severity.MEDIUM, "DKIM validation failed", "eml_parser", {"dkim": dkim})

            # Check DMARC
            dmarc = auth.get("dmarc", {})
            if dmarc.get("result") == "fail":
                context.scorer.add_finding(Severity.HIGH, "DMARC validation failed", "eml_parser", {"dmarc": dmarc})

            # Extract attachment hashes
            attachments = result.get("attachments", [])
            for att in attachments:
                if att.get("md5"):
                    context.add_iocs("hashes", [att["md5"]])
                if att.get("sha256"):
                    context.add_iocs("hashes", [att["sha256"]])

            return StepResult(step_name="parse_email", success=True, data=result)

        except ImportError:
            return StepResult(step_name="parse_email", success=False, error="EML parser not available")
        except Exception as e:
            return StepResult(step_name="parse_email", success=False, error=str(e))

    def _extract_iocs(self, context: WorkflowContext) -> StepResult:
        """Extract IOCs from email content"""
        try:
            from iocExtractor.extractor import IOCExtractor

            extractor = IOCExtractor(exclude_private_ips=True)
            result = extractor.extract_from_file(context.input_value)

            context.add_tool_result("ioc_extractor", result)

            # Add IOCs to context
            context.add_iocs("hashes", result.get("md5", []) + result.get("sha1", []) + result.get("sha256", []))
            context.add_iocs("domains", result.get("domains", []))
            context.add_iocs("ips", result.get("ips", []))
            context.add_iocs("urls", result.get("urls", []))
            context.add_iocs("emails", result.get("emails", []))

            # Flag if many IOCs found (potential phishing indicator)
            total_iocs = sum(len(v) for v in context.iocs.values())
            if total_iocs > 10:
                context.scorer.add_finding(
                    Severity.LOW,
                    f"Email contains many IOCs ({total_iocs}) - potential phishing",
                    "ioc_extractor",
                    {"total_iocs": total_iocs},
                )

            return StepResult(step_name="extract_iocs", success=True, data=result)

        except ImportError:
            return StepResult(step_name="extract_iocs", success=False, error="IOC extractor not available")
        except Exception as e:
            return StepResult(step_name="extract_iocs", success=False, error=str(e))

    def _check_hashes(self, context: WorkflowContext) -> StepResult:
        """Check attachment hashes against threat intelligence"""
        hashes = context.iocs.get("hashes", [])
        if not hashes:
            return StepResult(step_name="check_hashes", success=True, data={"message": "No hashes to check"})

        try:
            from hashLookup.lookup import HashLookup

            lookup = HashLookup(verbose=self.verbose)
            results = []

            for hash_val in hashes[:5]:  # Limit to 5 to avoid rate limiting
                result = lookup.lookup(hash_val)
                results.append(result)

                # Add findings based on results
                if result.get("verdict") == "malicious":
                    context.scorer.add_finding(
                        Severity.CRITICAL, f"Attachment hash is MALICIOUS: {hash_val[:16]}...", "hash_lookup", result
                    )
                elif result.get("verdict") == "suspicious":
                    context.scorer.add_finding(
                        Severity.HIGH, f"Attachment hash is suspicious: {hash_val[:16]}...", "hash_lookup", result
                    )

            context.add_tool_result("hash_lookup", {"results": results})
            return StepResult(step_name="check_hashes", success=True, data={"results": results})

        except ImportError:
            return StepResult(step_name="check_hashes", success=False, error="Hash lookup not available")
        except Exception as e:
            return StepResult(step_name="check_hashes", success=False, error=str(e))

    def _check_domains(self, context: WorkflowContext) -> StepResult:
        """Check domains against reputation services"""
        domains = context.iocs.get("domains", [])
        if not domains:
            return StepResult(step_name="check_domains", success=True, data={"message": "No domains to check"})

        try:
            from domainIpIntel.intel import DomainIPIntelligence as DomainIPIntel

            intel = DomainIPIntel(verbose=self.verbose)
            results = []

            for domain in domains[:5]:  # Limit to avoid rate limiting
                result = intel.lookup(domain)
                results.append(result)

                # Add findings
                if result.get("verdict") == "malicious":
                    context.scorer.add_finding(Severity.CRITICAL, f"Domain is MALICIOUS: {domain}", "domain_intel", result)
                elif result.get("verdict") == "suspicious":
                    context.scorer.add_finding(Severity.HIGH, f"Domain is suspicious: {domain}", "domain_intel", result)

                # Check domain age if available
                if result.get("domain_age_days", 999) < 30:
                    context.scorer.add_finding(
                        Severity.MEDIUM,
                        f"Domain recently registered ({result.get('domain_age_days')} days): {domain}",
                        "domain_intel",
                        {"domain": domain, "age_days": result.get("domain_age_days")},
                    )

            context.add_tool_result("domain_intel", {"results": results})
            return StepResult(step_name="check_domains", success=True, data={"results": results})

        except ImportError:
            return StepResult(step_name="check_domains", success=False, error="Domain intel not available")
        except Exception as e:
            return StepResult(step_name="check_domains", success=False, error=str(e))

    def _check_urls(self, context: WorkflowContext) -> StepResult:
        """Analyze URLs for malicious indicators"""
        urls = context.iocs.get("urls", [])
        if not urls:
            return StepResult(step_name="check_urls", success=True, data={"message": "No URLs to check"})

        try:
            from urlAnalyzer.analyzer import URLAnalyzer

            analyzer = URLAnalyzer(verbose=self.verbose)
            results = []

            for url in urls[:5]:  # Limit to avoid rate limiting
                result = analyzer.analyze(url)
                results.append(result)

                # Add findings
                if result.get("verdict") == "malicious":
                    context.scorer.add_finding(Severity.CRITICAL, f"URL is MALICIOUS: {url[:50]}...", "url_analyzer", result)
                elif result.get("verdict") == "suspicious":
                    context.scorer.add_finding(Severity.HIGH, f"URL is suspicious: {url[:50]}...", "url_analyzer", result)

                # Check for suspicious patterns
                patterns = result.get("suspicious_patterns", [])
                if patterns:
                    context.scorer.add_finding(
                        Severity.MEDIUM,
                        f"URL has suspicious patterns: {', '.join(patterns[:3])}",
                        "url_analyzer",
                        {"url": url, "patterns": patterns},
                    )

            context.add_tool_result("url_analyzer", {"results": results})
            return StepResult(step_name="check_urls", success=True, data={"results": results})

        except ImportError:
            return StepResult(step_name="check_urls", success=False, error="URL analyzer not available")
        except Exception as e:
            return StepResult(step_name="check_urls", success=False, error=str(e))

    def _check_certificates(self, context: WorkflowContext) -> StepResult:
        """Analyze certificates from URLs"""
        urls = [u for u in context.iocs.get("urls", []) if u.startswith("https://")]
        if not urls:
            return StepResult(step_name="check_certificates", success=True, data={"message": "No HTTPS URLs to check"})

        try:
            from certAnalyzer.analyzer import CertAnalyzer

            analyzer = CertAnalyzer(verbose=self.verbose)
            results = []

            for url in urls[:3]:  # Limit checks
                try:
                    result = analyzer.analyze(url)
                    results.append(result)

                    # Check for certificate issues
                    if result.get("verdict") == "suspicious":
                        context.scorer.add_finding(
                            Severity.HIGH, f"Certificate issues detected for: {url[:50]}", "cert_analyzer", result
                        )

                    # Check for phishing indicators
                    if result.get("phishing_indicators"):
                        context.scorer.add_finding(
                            Severity.HIGH,
                            "Certificate has phishing indicators",
                            "cert_analyzer",
                            result.get("phishing_indicators"),
                        )

                except Exception:
                    continue

            context.add_tool_result("cert_analyzer", {"results": results})
            return StepResult(step_name="check_certificates", success=True, data={"results": results})

        except ImportError:
            return StepResult(step_name="check_certificates", success=False, error="Certificate analyzer not available")
        except Exception as e:
            return StepResult(step_name="check_certificates", success=False, error=str(e))

    def _calculate_score(self, context: WorkflowContext) -> StepResult:
        """Calculate final phishing probability score"""
        # Score is already accumulated in context.scorer
        summary = context.scorer.get_summary()

        # Add phishing-specific recommendations
        recommendations = []

        if summary["risk_score"] >= 70:
            recommendations.extend(
                [
                    "Block sender domain at email gateway immediately",
                    "Search for similar emails across the organization",
                    "Alert all recipients of this email",
                    "Block identified malicious URLs at proxy",
                    "Submit attachments to sandbox for analysis",
                ]
            )
        elif summary["risk_score"] >= 40:
            recommendations.extend(
                [
                    "Flag sender domain for monitoring",
                    "Warn recipients about potential phishing",
                    "Review email gateway logs for similar patterns",
                ]
            )
        else:
            recommendations.append("Continue normal monitoring")

        return StepResult(
            step_name="calculate_score",
            success=True,
            data={"risk_score": summary["risk_score"], "verdict": summary["verdict"], "recommendations": recommendations},
        )
