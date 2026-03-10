"""
vlair AI Classifier — Heuristic malware family classifier.

Classifies malware families from VirusTotal detection data and threat-intel tool
results using rule-based heuristics.  No ML model is required.
"""

import re
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Family signature database
# ---------------------------------------------------------------------------

FAMILY_SIGNATURES: dict = {
    "emotet": {
        "tags": ["emotet", "heodo", "geodo", "mealybug"],
        "behaviors": ["scheduled task", "registry run key", "lateral movement", "credential stealing"],
        "vt_labels": ["emotet", "heodo", "geodo"],
        "severity": "critical",
        "category": "banking_trojan_loader",
        "threat_actor": "TA542",
        "mitre_techniques": ["T1566.001", "T1059.001", "T1053.005", "T1021.002", "T1078"],
        "description": "Banking trojan and malware loader responsible for mass spam campaigns.",
    },
    "cobalt_strike": {
        "tags": ["cobalt strike", "cobaltstrike", "beacon", "cs-beacon", "cobeacon"],
        "behaviors": ["named pipe", "beacon", "reflective dll", "process injection"],
        "vt_labels": ["cobalt", "cobaltstrike", "beacon"],
        "severity": "critical",
        "category": "post_exploitation",
        "threat_actor": None,
        "mitre_techniques": ["T1055", "T1071.001", "T1105", "T1059.003", "T1021.006"],
        "description": "Commercial penetration-testing framework widely abused by threat actors.",
    },
    "qakbot": {
        "tags": ["qakbot", "qbot", "quakbot", "pinkslipbot"],
        "behaviors": ["browser credential theft", "email hijacking", "lateral movement"],
        "vt_labels": ["qakbot", "qbot", "quakbot"],
        "severity": "critical",
        "category": "banking_trojan_loader",
        "threat_actor": None,
        "mitre_techniques": ["T1566.001", "T1059.001", "T1071.001", "T1003.001"],
        "description": "Banking trojan turned malware loader / ransomware precursor.",
    },
    "trickbot": {
        "tags": ["trickbot", "trickster", "trickbooster"],
        "behaviors": ["rdp credential theft", "kerberos ticket", "lateral movement"],
        "vt_labels": ["trickbot", "trickster"],
        "severity": "critical",
        "category": "banking_trojan_loader",
        "threat_actor": None,
        "mitre_techniques": ["T1566.001", "T1557.001", "T1098", "T1021.001"],
        "description": "Modular banking trojan commonly used as a precursor to ransomware.",
    },
    "ryuk": {
        "tags": ["ryuk", "hermes"],
        "behaviors": ["file encryption", "shadow copy deletion", "ransomware"],
        "vt_labels": ["ryuk", "hermes"],
        "severity": "critical",
        "category": "ransomware",
        "threat_actor": "WIZARD SPIDER",
        "mitre_techniques": ["T1486", "T1490", "T1059.003", "T1070.004"],
        "description": "Big-game hunting ransomware targeting enterprises, healthcare, and government.",
    },
    "lockbit": {
        "tags": ["lockbit", "lockbit2", "lockbit3", "lockbit 2.0", "lockbit 3.0"],
        "behaviors": ["file encryption", "shadow copy deletion", "self-propagation"],
        "vt_labels": ["lockbit"],
        "severity": "critical",
        "category": "ransomware",
        "threat_actor": "LOCKBIT",
        "mitre_techniques": ["T1486", "T1490", "T1021.002", "T1083", "T1135"],
        "description": "Prolific ransomware-as-a-service operation with fast encryption.",
    },
    "conti": {
        "tags": ["conti", "contiv2", "wizard spider"],
        "behaviors": ["file encryption", "shadow copy deletion", "lateral movement"],
        "vt_labels": ["conti"],
        "severity": "critical",
        "category": "ransomware",
        "threat_actor": "WIZARD SPIDER",
        "mitre_techniques": ["T1486", "T1490", "T1021.002", "T1082"],
        "description": "Ransomware-as-a-service operated by WIZARD SPIDER group.",
    },
    "mimikatz": {
        "tags": ["mimikatz", "mimilib", "sekurlsa"],
        "behaviors": ["credential dumping", "pass-the-hash", "kerberos ticket"],
        "vt_labels": ["mimikatz"],
        "severity": "high",
        "category": "credential_theft",
        "threat_actor": None,
        "mitre_techniques": ["T1003.001", "T1550.002", "T1558.003"],
        "description": "Open-source credential-dumping tool used by many threat actors.",
    },
    "metasploit": {
        "tags": ["metasploit", "meterpreter", "msf", "metaspl"],
        "behaviors": ["process injection", "reverse shell", "privilege escalation"],
        "vt_labels": ["metasploit", "meterpreter"],
        "severity": "high",
        "category": "post_exploitation",
        "threat_actor": None,
        "mitre_techniques": ["T1055", "T1059", "T1548.002"],
        "description": "Penetration-testing framework; meterpreter payload commonly seen in attacks.",
    },
    "njrat": {
        "tags": ["njrat", "bladabindi", "njw0rm"],
        "behaviors": ["keylogging", "remote shell", "file manager", "webcam access"],
        "vt_labels": ["njrat", "bladabindi"],
        "severity": "high",
        "category": "rat",
        "threat_actor": None,
        "mitre_techniques": ["T1056.001", "T1059.003", "T1071.001"],
        "description": "Remote Access Trojan popular in Middle East threat campaigns.",
    },
    "remcos": {
        "tags": ["remcos", "remcosrat"],
        "behaviors": ["keylogging", "screen capture", "remote shell", "file download"],
        "vt_labels": ["remcos"],
        "severity": "high",
        "category": "rat",
        "threat_actor": None,
        "mitre_techniques": ["T1056.001", "T1113", "T1059.003", "T1105"],
        "description": "Commercial RAT often distributed via phishing and malspam campaigns.",
    },
    "asyncrat": {
        "tags": ["asyncrat", "asyncremotetool"],
        "behaviors": ["keylogging", "remote shell", "process manager", "persistence"],
        "vt_labels": ["asyncrat", "asyncremote"],
        "severity": "high",
        "category": "rat",
        "threat_actor": None,
        "mitre_techniques": ["T1056.001", "T1059.003", "T1547.001"],
        "description": "Open-source .NET RAT with strong evasion capabilities.",
    },
    "redline": {
        "tags": ["redline", "redlinestealer", "redline stealer"],
        "behaviors": ["credential stealing", "browser theft", "crypto wallet theft"],
        "vt_labels": ["redline"],
        "severity": "high",
        "category": "infostealer",
        "threat_actor": None,
        "mitre_techniques": ["T1555.003", "T1056.001", "T1041"],
        "description": "Information stealer targeting browsers, crypto wallets, and credentials.",
    },
    "formbook": {
        "tags": ["formbook", "xloader"],
        "behaviors": ["form grabbing", "keylogging", "screenshot"],
        "vt_labels": ["formbook", "xloader"],
        "severity": "high",
        "category": "infostealer",
        "threat_actor": None,
        "mitre_techniques": ["T1056.003", "T1056.001", "T1113"],
        "description": "Form-grabbing infostealer sold as MaaS; rebranded as XLoader.",
    },
    "agent_tesla": {
        "tags": ["agent tesla", "agenttesla", "agenttelsa"],
        "behaviors": ["keylogging", "screenshot", "credential stealing", "email exfil"],
        "vt_labels": ["agenttesla", "agent tesla"],
        "severity": "high",
        "category": "infostealer",
        "threat_actor": None,
        "mitre_techniques": ["T1056.001", "T1113", "T1048.003"],
        "description": ".NET keylogger / infostealer sold as a commodity malware kit.",
    },
    "icedid": {
        "tags": ["icedid", "bokbot"],
        "behaviors": ["browser injection", "webinject", "banking fraud", "loader"],
        "vt_labels": ["icedid", "bokbot"],
        "severity": "critical",
        "category": "banking_trojan_loader",
        "threat_actor": None,
        "mitre_techniques": ["T1566.001", "T1059.001", "T1071.001", "T1055"],
        "description": "Banking trojan acting as a loader for ransomware groups.",
    },
    "dridex": {
        "tags": ["dridex", "bugat", "feodo"],
        "behaviors": ["banking fraud", "credential theft", "spam module", "lateral movement"],
        "vt_labels": ["dridex", "bugat"],
        "severity": "critical",
        "category": "banking_trojan_loader",
        "threat_actor": "TA505",
        "mitre_techniques": ["T1566.001", "T1003.001", "T1021.002"],
        "description": "Sophisticated banking trojan linked to TA505 / Evil Corp.",
    },
    "ursnif": {
        "tags": ["ursnif", "gozi", "isfb"],
        "behaviors": ["banking fraud", "form grabbing", "keylogging"],
        "vt_labels": ["ursnif", "gozi", "isfb"],
        "severity": "high",
        "category": "banking_trojan",
        "threat_actor": None,
        "mitre_techniques": ["T1056.003", "T1056.001", "T1071.001"],
        "description": "Long-running banking trojan family (Gozi / ISFB lineage).",
    },
    "gh0strat": {
        "tags": ["gh0st", "gh0strat", "ghost rat"],
        "behaviors": ["remote shell", "keylogging", "screen capture", "file manager"],
        "vt_labels": ["gh0st", "ghostrat"],
        "severity": "high",
        "category": "rat",
        "threat_actor": None,
        "mitre_techniques": ["T1059.003", "T1056.001", "T1113"],
        "description": "Open-source Chinese RAT widely reused in espionage campaigns.",
    },
    "wannacry": {
        "tags": ["wannacry", "wcry", "wanna decryptor", "wannadecryptor"],
        "behaviors": ["file encryption", "smb exploit", "lateral movement", "ransomware"],
        "vt_labels": ["wannacry", "wcry"],
        "severity": "critical",
        "category": "ransomware_worm",
        "threat_actor": "LAZARUS GROUP",
        "mitre_techniques": ["T1486", "T1210", "T1490"],
        "description": "Ransomware worm exploiting EternalBlue (MS17-010), attributed to DPRK.",
    },
    "notpetya": {
        "tags": ["petya", "notpetya", "nyetya", "expetr"],
        "behaviors": ["mbr wipe", "credential stealing", "worm", "destructive"],
        "vt_labels": ["petya", "notpetya"],
        "severity": "critical",
        "category": "destructive_worm",
        "threat_actor": "SANDWORM",
        "mitre_techniques": ["T1561.002", "T1003.001", "T1210"],
        "description": "Destructive pseudo-ransomware worm attributed to Russian SANDWORM.",
    },
    "sliver": {
        "tags": ["sliver", "bishopfox"],
        "behaviors": ["reverse shell", "process injection", "c2 beacon"],
        "vt_labels": ["sliver"],
        "severity": "high",
        "category": "post_exploitation",
        "threat_actor": None,
        "mitre_techniques": ["T1055", "T1071.001", "T1059"],
        "description": "Open-source C2 framework used as Cobalt Strike alternative.",
    },
}


# ---------------------------------------------------------------------------
# Main classifier
# ---------------------------------------------------------------------------


class MalwareClassifier:
    """
    Rule-based malware family classifier.

    Accepts the dict output of vlair tools (hash_lookup, analyze, etc.) and
    returns a classification result including family name, confidence, MITRE
    techniques, and threat actor attribution.
    """

    def __init__(self) -> None:
        self._signatures = FAMILY_SIGNATURES

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def classify(self, tool_result: dict) -> dict:
        """
        Classify malware family from a vlair tool result.

        Args:
            tool_result: Dict output from hash_lookup, analyze, or similar.

        Returns:
            {
                "family": "emotet",
                "confidence": 0.92,
                "category": "banking_trojan_loader",
                "severity": "critical",
                "threat_actor": "TA542",
                "matching_signals": ["VT tag: emotet", "detection name: heodo"],
                "mitre_techniques": ["T1566.001", …],
                "description": "…",
            }
            or {"family": None, "confidence": 0.0, …} if unclassified.
        """
        signals = self._extract_signals(tool_result)
        scores: dict = {}

        for family, sig in self._signatures.items():
            score = 0
            matched: list = []

            # Check tags
            for tag in sig.get("tags", []):
                for signal in signals:
                    if tag.lower() in signal.lower():
                        score += 3
                        matched.append(f"tag match: {tag} in '{signal}'")

            # Check VT detection labels
            for label in sig.get("vt_labels", []):
                for signal in signals:
                    if label.lower() in signal.lower():
                        score += 2
                        matched.append(f"detection label: {label}")

            # Check behavioral indicators
            for behavior in sig.get("behaviors", []):
                for signal in signals:
                    if behavior.lower() in signal.lower():
                        score += 1
                        matched.append(f"behavior: {behavior}")

            if score > 0:
                scores[family] = {"score": score, "matched": list(set(matched))}

        if not scores:
            return {
                "family": None,
                "confidence": 0.0,
                "category": "unknown",
                "severity": "unknown",
                "threat_actor": None,
                "matching_signals": [],
                "mitre_techniques": [],
                "description": "Unable to classify — no matching signatures found.",
            }

        # Pick best match
        best_family = max(scores, key=lambda f: scores[f]["score"])
        best_score = scores[best_family]["score"]
        matched_signals = scores[best_family]["matched"]

        # Normalise confidence: cap at 0.97
        confidence = min(0.97, best_score / 10.0)

        sig = self._signatures[best_family]
        return {
            "family": best_family,
            "confidence": round(confidence, 3),
            "category": sig.get("category", "unknown"),
            "severity": sig.get("severity", "unknown"),
            "threat_actor": sig.get("threat_actor"),
            "matching_signals": matched_signals[:10],
            "mitre_techniques": sig.get("mitre_techniques", []),
            "description": sig.get("description", ""),
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _extract_signals(self, tool_result: dict) -> list:
        """
        Flatten all string values from a tool result into a list of signal strings
        for matching against family signatures.
        """
        signals: list = []

        def _collect(obj: Any) -> None:
            if isinstance(obj, str):
                signals.append(obj)
            elif isinstance(obj, list):
                for item in obj:
                    _collect(item)
            elif isinstance(obj, dict):
                for val in obj.values():
                    _collect(val)

        # Prioritise common high-signal fields
        high_signal_fields = [
            "family_labels",
            "malware_family",
            "suggested_threat_label",
            "names",
            "tags",
            "categories",
            "threat_names",
            "detection_names",
            "malware_names",
            "threat_categories",
            "verdict",
            "type_description",
        ]
        for field in high_signal_fields:
            val = tool_result.get(field)
            if val is not None:
                _collect(val)

        # Also walk the full result for completeness
        _collect(tool_result)

        return signals
