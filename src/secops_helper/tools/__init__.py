"""
SecOps Helper Tools - Security operations toolset

Available tools:
- eml_parser: Email analysis and parsing
- ioc_extractor: IOC extraction from text
- hash_lookup: Hash reputation lookup
- domain_ip_intel: Domain/IP intelligence
- log_analyzer: Log file analysis
- pcap_analyzer: Network traffic analysis
- url_analyzer: URL threat analysis
- yara_scanner: YARA malware scanning
- cert_analyzer: SSL/TLS certificate analysis
- deobfuscator: Script deobfuscation
- threat_feed_aggregator: Threat intelligence aggregation
- file_carver: File carving and extraction
"""

# Import main classes from each tool for easy access
# These are imported lazily when needed to avoid heavy startup costs

__all__ = [
    # Tool module names
    "eml_parser",
    "ioc_extractor",
    "hash_lookup",
    "domain_ip_intel",
    "log_analyzer",
    "pcap_analyzer",
    "url_analyzer",
    "yara_scanner",
    "cert_analyzer",
    "deobfuscator",
    "threat_feed_aggregator",
    "file_carver",
]


def get_tool_registry():
    """
    Get registry of all available tools with their metadata.

    Returns:
        Dict mapping tool IDs to their metadata including:
        - name: Display name
        - module: Python module path
        - category: Tool category for grouping
        - description: Brief description
        - keywords: Search keywords
        - examples: Usage examples
        - requires_api: List of API keys needed
    """
    return {
        "eml": {
            "name": "EML Parser",
            "module": "secops_helper.tools.eml_parser",
            "category": "Email Analysis",
            "description": "Parse and analyze email files (.eml) with attachment hashing and header analysis",
            "keywords": [
                "email",
                "eml",
                "phishing",
                "attachment",
                "header",
                "spf",
                "dkim",
                "dmarc",
            ],
            "examples": [
                "secops eml suspicious.eml --vt",
                "secops eml phishing.eml --output report.json",
            ],
            "requires_api": ["VT_API_KEY (optional)"],
        },
        "ioc": {
            "name": "IOC Extractor",
            "module": "secops_helper.tools.ioc_extractor",
            "category": "Threat Intelligence",
            "description": "Extract indicators of compromise (IPs, domains, URLs, hashes, CVEs) from text",
            "keywords": ["ioc", "indicator", "ip", "domain", "url", "hash", "cve", "extract"],
            "examples": [
                "secops ioc threat_report.txt",
                "secops ioc --file report.txt --format csv --defang",
            ],
            "requires_api": [],
        },
        "hash": {
            "name": "Hash Lookup",
            "module": "secops_helper.tools.hash_lookup",
            "category": "Threat Intelligence",
            "description": "Look up file hashes against VirusTotal and MalwareBazaar",
            "keywords": ["hash", "md5", "sha1", "sha256", "virustotal", "malware", "threat"],
            "examples": [
                "secops hash 44d88612fea8a8f36de82e1278abb02f",
                "secops hash --file hashes.txt --verbose",
            ],
            "requires_api": ["VT_API_KEY (optional)"],
        },
        "intel": {
            "name": "Domain/IP Intelligence",
            "module": "secops_helper.tools.domain_ip_intel",
            "category": "Threat Intelligence",
            "description": "Analyze domains and IP addresses with threat intelligence and DNS resolution",
            "keywords": ["domain", "ip", "dns", "whois", "reputation", "threat", "intelligence"],
            "examples": ["secops intel malicious.com", "secops intel 1.2.3.4 --verbose"],
            "requires_api": ["VT_API_KEY", "ABUSEIPDB_KEY (optional)"],
        },
        "log": {
            "name": "Log Analyzer",
            "module": "secops_helper.tools.log_analyzer",
            "category": "Log Analysis",
            "description": "Analyze Apache, Nginx, and syslog files for security threats",
            "keywords": ["log", "apache", "nginx", "syslog", "attack", "web", "security"],
            "examples": [
                "secops log /var/log/apache2/access.log",
                "secops log nginx.log --type nginx --format txt",
            ],
            "requires_api": [],
        },
        "pcap": {
            "name": "PCAP Analyzer",
            "module": "secops_helper.tools.pcap_analyzer",
            "category": "Network Analysis",
            "description": "Analyze network traffic captures for threats and anomalies",
            "keywords": ["pcap", "network", "traffic", "packet", "dns", "http", "scan"],
            "examples": [
                "secops pcap capture.pcap",
                "secops pcap traffic.pcapng --verbose --output analysis.json",
            ],
            "requires_api": [],
        },
        "url": {
            "name": "URL Analyzer",
            "module": "secops_helper.tools.url_analyzer",
            "category": "Threat Intelligence",
            "description": "Analyze URLs for threats, phishing, and malware",
            "keywords": ["url", "link", "phishing", "malware", "suspicious", "threat"],
            "examples": [
                'secops url "http://suspicious-site.com"',
                "secops url --file urls.txt --format json",
            ],
            "requires_api": ["VT_API_KEY (optional)"],
        },
        "yara": {
            "name": "YARA Scanner",
            "module": "secops_helper.tools.yara_scanner",
            "category": "Malware Analysis",
            "description": "Scan files and directories with YARA malware detection rules",
            "keywords": ["yara", "malware", "scan", "signature", "rule", "detection"],
            "examples": [
                "secops yara scan /samples/ --rules ./rules/",
                "secops yara scan malware.exe --rules custom.yar",
            ],
            "requires_api": [],
        },
        "cert": {
            "name": "Certificate Analyzer",
            "module": "secops_helper.tools.cert_analyzer",
            "category": "SSL/TLS Analysis",
            "description": "Analyze SSL/TLS certificates for security issues and phishing",
            "keywords": ["certificate", "ssl", "tls", "https", "x509", "phishing", "crypto"],
            "examples": [
                "secops cert https://example.com",
                "secops cert --file cert.pem --hostname example.com",
            ],
            "requires_api": [],
        },
        "deobfuscate": {
            "name": "Script Deobfuscator",
            "module": "secops_helper.tools.deobfuscator",
            "category": "Malware Analysis",
            "description": "Deobfuscate PowerShell, JavaScript, VBScript, and other malicious scripts",
            "keywords": ["deobfuscate", "powershell", "javascript", "vbscript", "decode", "base64"],
            "examples": [
                "secops deobfuscate malware.js --extract-iocs",
                "secops deobfuscate script.ps1 --language powershell",
            ],
            "requires_api": [],
        },
        "threatfeed": {
            "name": "Threat Feed Aggregator",
            "module": "secops_helper.tools.threat_feed_aggregator",
            "category": "Threat Intelligence",
            "description": "Aggregate and manage threat intelligence feeds from multiple sources",
            "keywords": ["threat", "feed", "ioc", "aggregator", "threatfox", "urlhaus"],
            "examples": [
                "secops threatfeed update --source all",
                "secops threatfeed search --type domain --confidence 80",
            ],
            "requires_api": [],
        },
        "carve": {
            "name": "File Carver",
            "module": "secops_helper.tools.file_carver",
            "category": "Forensics",
            "description": "Extract embedded files from disk images, memory dumps, and binary files",
            "keywords": ["carve", "forensics", "extract", "file", "disk", "memory", "dump"],
            "examples": [
                "secops carve --image disk.dd --output /carved/",
                "secops carve --image memdump.raw --types exe,dll,pdf",
            ],
            "requires_api": [],
        },
    }
