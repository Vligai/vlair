"""
vlair AI Correlator — Multi-IOC correlation to identify campaign patterns.
"""

import hashlib
from collections import defaultdict
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Known infrastructure / threat actor mapping (simplified)
# ---------------------------------------------------------------------------

_KNOWN_THREAT_ACTORS: dict = {
    "TA542": ["emotet", "heodo", "geodo"],
    "TA505": ["dridex", "clop", "flawed ammyy"],
    "LAZARUS": ["wannacry", "lazarus", "hidden cobra", "bluenoroff"],
    "WIZARD SPIDER": ["ryuk", "conti", "trickbot", "bazarloader"],
    "SANDWORM": ["notpetya", "industroyer", "sandworm"],
    "APT29": ["cozy bear", "apt29", "nobelium", "sunburst", "solarwinds"],
    "APT28": ["fancy bear", "apt28", "sofacy", "sednit"],
    "CARBANAK": ["carbanak", "fin7", "navigator"],
}


class IOCCorrelator:
    """
    Correlate multiple IOC results to identify shared infrastructure, campaigns,
    and threat actor patterns.
    """

    def correlate(self, iocs: list, tool_results: list) -> dict:
        """
        Find relationships between multiple IOCs.

        Args:
            iocs:         List of IOC values (strings).
            tool_results: Corresponding tool result dicts (same length as iocs).

        Returns:
            {
                "campaign_indicators":  [...],   # Shared infrastructure signals
                "related_iocs":         {...},    # By relationship type
                "attribution":          "...",    # Likely threat actor
                "confidence":           0.7,
                "relationships":        [...],    # Explicit relationship list
                "shared_signals":       [...],    # Signals seen across multiple IOCs
                "summary":              "...",
            }
        """
        if not iocs:
            return self._empty_result()

        # Normalise lengths
        results = list(tool_results) + [{}] * max(0, len(iocs) - len(tool_results))
        results = results[: len(iocs)]

        # Extract signals per IOC
        ioc_signals: list = []
        for ioc, result in zip(iocs, results):
            signals = self._extract_signals(ioc, result)
            ioc_signals.append(signals)

        # Find shared signals across IOCs
        all_signals: dict = defaultdict(list)
        for i, signals in enumerate(ioc_signals):
            for sig in signals.get("tags", []):
                all_signals[sig].append(iocs[i])
            for sig in signals.get("families", []):
                all_signals[sig].append(iocs[i])
            for sig in signals.get("asns", []):
                all_signals[sig].append(iocs[i])
            for sig in signals.get("registrars", []):
                all_signals[sig].append(iocs[i])

        campaign_indicators = []
        shared_signals = []
        for signal, ioc_list in all_signals.items():
            if len(ioc_list) >= 2:
                campaign_indicators.append(signal)
                shared_signals.append(
                    {
                        "signal": signal,
                        "iocs": list(set(ioc_list)),
                        "count": len(set(ioc_list)),
                    }
                )

        # Build relationship list
        relationships = self._build_relationships(iocs, ioc_signals)

        # Threat actor attribution
        attribution, attr_confidence = self._attribute(ioc_signals)

        # Overall confidence
        confidence = self._calculate_confidence(
            n_iocs=len(iocs),
            n_campaign_indicators=len(campaign_indicators),
            attr_confidence=attr_confidence,
        )

        # Group related IOCs by relationship type
        related_iocs = self._group_related(relationships)

        summary = self._summarize(
            iocs, campaign_indicators, attribution, attr_confidence, relationships
        )

        return {
            "campaign_indicators": campaign_indicators,
            "related_iocs": related_iocs,
            "attribution": attribution,
            "confidence": round(confidence, 3),
            "relationships": relationships,
            "shared_signals": shared_signals,
            "summary": summary,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _empty_result(self) -> dict:
        return {
            "campaign_indicators": [],
            "related_iocs": {},
            "attribution": None,
            "confidence": 0.0,
            "relationships": [],
            "shared_signals": [],
            "summary": "No IOCs provided for correlation.",
        }

    def _extract_signals(self, ioc: str, result: dict) -> dict:
        """Extract classification signals from a single tool result."""
        signals: dict = {
            "tags": [],
            "families": [],
            "asns": [],
            "registrars": [],
            "countries": [],
            "categories": [],
        }

        def _collect_strings(obj: Any, dest: list) -> None:
            if isinstance(obj, str) and obj.strip():
                dest.append(obj.strip().lower())
            elif isinstance(obj, list):
                for item in obj:
                    _collect_strings(item, dest)

        # Tags / families
        for key in ("tags", "family_labels", "malware_family", "suggested_threat_label", "names"):
            _collect_strings(result.get(key, []), signals["tags"])

        for key in ("categories", "threat_categories", "type_description"):
            _collect_strings(result.get(key, []), signals["categories"])

        # Network / registration signals
        asn = result.get("asn") or result.get("as_number")
        if asn:
            signals["asns"].append(str(asn))

        country = result.get("country") or result.get("country_code")
        if country:
            signals["countries"].append(str(country).upper())

        registrar = result.get("registrar")
        if registrar:
            signals["registrars"].append(str(registrar).lower())

        # DNS-based signals
        dns = result.get("dns", {})
        if isinstance(dns, dict):
            for ns in dns.get("ns_records", []):
                signals["registrars"].append(str(ns).lower())

        return signals

    def _build_relationships(self, iocs: list, ioc_signals: list) -> list:
        """Build pairwise relationships between IOCs."""
        relationships = []
        for i in range(len(iocs)):
            for j in range(i + 1, len(iocs)):
                common_tags = set(ioc_signals[i].get("tags", [])) & set(
                    ioc_signals[j].get("tags", [])
                )
                common_asns = set(ioc_signals[i].get("asns", [])) & set(
                    ioc_signals[j].get("asns", [])
                )
                common_regs = set(ioc_signals[i].get("registrars", [])) & set(
                    ioc_signals[j].get("registrars", [])
                )

                if common_tags or common_asns or common_regs:
                    rel_types = []
                    if common_tags:
                        rel_types.append("shared_malware_family")
                    if common_asns:
                        rel_types.append("shared_asn")
                    if common_regs:
                        rel_types.append("shared_registrar")

                    relationships.append(
                        {
                            "ioc_a": iocs[i],
                            "ioc_b": iocs[j],
                            "relationship_types": rel_types,
                            "common_tags": list(common_tags),
                            "common_asns": list(common_asns),
                            "common_registrars": list(common_regs),
                        }
                    )
        return relationships

    def _attribute(self, ioc_signals: list) -> tuple:
        """Attempt to attribute IOCs to a known threat actor. Returns (actor, confidence)."""
        all_tags: list = []
        for signals in ioc_signals:
            all_tags.extend(signals.get("tags", []))
            all_tags.extend(signals.get("families", []))
        all_tags_lower = " ".join(all_tags).lower()

        best_actor = None
        best_score = 0

        for actor, keywords in _KNOWN_THREAT_ACTORS.items():
            score = sum(1 for kw in keywords if kw.lower() in all_tags_lower)
            if score > best_score:
                best_score = score
                best_actor = actor

        if best_actor and best_score > 0:
            confidence = min(0.90, best_score * 0.25)
        else:
            confidence = 0.0
            best_actor = None

        return best_actor, confidence

    def _calculate_confidence(
        self, n_iocs: int, n_campaign_indicators: int, attr_confidence: float
    ) -> float:
        """Compute overall correlation confidence."""
        base = 0.0
        if n_iocs >= 2:
            base += 0.2
        if n_campaign_indicators >= 1:
            base += 0.3
        if n_campaign_indicators >= 3:
            base += 0.2
        base += attr_confidence * 0.3
        return min(0.95, base)

    def _group_related(self, relationships: list) -> dict:
        """Group IOCs by relationship type."""
        groups: dict = defaultdict(set)
        for rel in relationships:
            for rtype in rel.get("relationship_types", []):
                groups[rtype].add(rel["ioc_a"])
                groups[rtype].add(rel["ioc_b"])
        return {k: sorted(v) for k, v in groups.items()}

    def _summarize(
        self,
        iocs: list,
        campaign_indicators: list,
        attribution: Optional[str],
        attr_confidence: float,
        relationships: list,
    ) -> str:
        parts = [f"Analyzed {len(iocs)} IOC(s)."]
        if relationships:
            parts.append(f"Found {len(relationships)} pairwise relationship(s).")
        if campaign_indicators:
            parts.append(f"Shared campaign indicators: {', '.join(campaign_indicators[:5])}.")
        if attribution:
            parts.append(
                f"Possible attribution: {attribution} (confidence {int(attr_confidence * 100)}%)."
            )
        else:
            parts.append("No threat actor attribution established.")
        return " ".join(parts)
