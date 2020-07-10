"""
STIX 2.1 open vocabularies and enums
"""

ACCOUNT_TYPE = [
    "facebook",
    "ldap",
    "nis",
    "openid",
    "radius",
    "skype",
    "tacacs",
    "twitter",
    "unix",
    "windows-local",
    "windows-domain",
]


ATTACK_MOTIVATION = [
    "accidental",
    "coercion",
    "dominance",
    "ideology",
    "notoriety",
    "organizational-gain",
    "personal-gain",
    "personal-satisfaction",
    "revenge",
    "unpredictable",
]


ATTACK_RESOURCE_LEVEL = [
    "individual",
    "club",
    "contest",
    "team",
    "organization",
    "government",
]


ENCRYPTION_ALGORITHM = [
    "AES-256-GCM",
    "ChaCha20-Poly1305",
    "mime-type-indicated",
]


GROUPING_CONTEXT = [
    "suspicious-activity",
    "malware-analysis",
    "unspecified",
]


HASHING_ALGORITHM = [
    "MD5",
    "SHA-1",
    "SHA-256",
    "SHA-512",
    "SHA3-256",
    "SHA3-512",
    "SSDEEP",
    "TLSH",
]


IDENTITY_CLASS = [
    "individual",
    "group",
    "system",
    "organization",
    "class",
    "unknown",
]


IMPLEMENTATION_LANGUAGE = [
    "applescript",
    "bash",
    "c",
    "c++",
    "c#",
    "go",
    "java",
    "javascript",
    "lua",
    "objective-c",
    "perl",
    "php",
    "powershell",
    "python",
    "ruby",
    "scala",
    "swift",
    "typescript",
    "visual-basic",
    "x86-32",
    "x86-64",
]


INDICATOR_TYPE = [
    "anomalous-activity",
    "anonymization",
    "benign",
    "compromised",
    "malicious-activity",
    "attribution",
    "unknown",
]


INDUSTRY_SECTOR = [
    "agriculture",
    "aerospace",
    "automotive",
    "chemical",
    "commercial",
    "communications",
    "construction",
    "defense",
    "education",
    "energy",
    "entertainment",
    "financial-services",
    "government",
    "emergency-services",
    "government-national",
    "government-regional",
    "government-local",
    "government-public-services",
    "healthcare",
    "hospitality-leisure",
    "infrastructure",
    "dams",
    "nuclear",
    "water",
    "insurance",
    "manufacturing",
    "mining",
    "non-profit",
    "pharmaceuticals",
    "retail",
    "technology",
    "telecommunications",
    "transportation",
    "utilities",
]


INFRASTRUCTURE_TYPE = [
    "amplification",
    "anonymization",
    "botnet",
    "command-and-control",
    "exfiltration",
    "hosting-malware",
    "hosting-target-lists",
    "phishing",
    "reconnaissance",
    "staging",
    "unknown",
]


MALWARE_RESULT = [
    "malicious",
    "suspicious",
    "benign",
    "unknown",
]


MALWARE_CAPABILITIES = [
    "accesses-remote-machines",
    "anti-debugging",
    "anti-disassembly",
    "anti-emulation",
    "anti-memory-forensics",
    "anti-sandbox",
    "anti-vm",
    "captures-input-peripherals",
    "captures-output-peripherals",
    "captures-system-state-data",
    "cleans-traces-of-infection",
    "commits-fraud",
    "communicates-with-c2",
    "compromises-data-availability",
    "compromises-data-integrity",
    "compromises-system-availability",
    "controls-local-machine",
    "degrades-security-software",
    "degrades-system-updates",
    "determines-c2-server",
    "emails-spam",
    "escalates-privileges",
    "evades-av",
    "exfiltrates-data",
    "fingerprints-host",
    "hides-artifacts",
    "hides-executing-code",
    "infects-files",
    "infects-remote-machines",
    "installs-other-components",
    "persists-after-system-reboot",
    "prevents-artifact-access",
    "prevents-artifact-deletion",
    "probes-network-environment",
    "self-modifies",
    "steals-authentication-credentials",
    "violates-system-operational-integrity",
]


MALWARE_TYPE = [
    "adware",
    "backdoor",
    "bot",
    "bootkit",
    "ddos",
    "downloader",
    "dropper",
    "exploit-kit",
    "keylogger",
    "ransomware",
    "remote-access-trojan",
    "resource-exploitation",
    "rogue-security-software",
    "rootkit",
    "screen-capture",
    "spyware",
    "trojan",
    "unknown",
    "virus",
    "webshell",
    "wiper",
    "worm",
]


NETWORK_SOCKET_ADDRESS_FAMILY = [
    "AF_UNSPEC",
    "AF_INET",
    "AF_IPX",
    "AF_APPLETALK",
    "AF_NETBIOS",
    "AF_INET6",
    "AF_IRDA",
    "AF_BTH",
]


NETWORK_SOCKET_TYPE = [
    "SOCK_STREAM",
    "SOCK_DGRAM",
    "SOCK_RAW",
    "SOCK_RDM",
    "SOCK_SEQPACKET",
]


OPINION = [
    "strongly-disagree",
    "disagree",
    "neutral",
    "agree",
    "strongly-agree",
]


PATTERN_TYPE = [
    "stix",
    "pcre",
    "sigma",
    "snort",
    "suricata",
    "yara",
]


PROCESSOR_ARCHITECTURE = [
    "alpha",
    "arm",
    "ia-64",
    "mips",
    "powerpc",
    "sparc",
    "x86",
    "x86-64",
]


REGION = [
    "africa",
    "eastern-africa",
    "middle-africa",
    "northern-africa",
    "southern-africa",
    "western-africa",
    "americas",
    "latin-america-caribbean",
    "south-america",
    "caribbean",
    "central-america",
    "northern-america",
    "asia",
    "central-asia",
    "eastern-asia",
    "southern-asia",
    "south-eastern-asia",
    "western-asia",
    "europe",
    "eastern-europe",
    "northern-europe",
    "southern-europe",
    "western-europe",
    "oceania",
    "antarctica",
    "australia-new-zealand",
    "melanesia",
    "micronesia",
    "polynesia",
]


REPORT_TYPE = [
    "attack-pattern",
    "campaign",
    "identity",
    "indicator",
    "intrusion-set",
    "malware",
    "observed-data",
    "threat-actor",
    "threat-report",
    "tool",
    "vulnerability",
]


THREAT_ACTOR_TYPE = [
    "activist",
    "competitor",
    "crime-syndicate",
    "criminal",
    "hacker",
    "insider-accidental",
    "insider-disgruntled",
    "nation-state",
    "sensationalist",
    "spy",
    "terrorist",
    "unknown",
]


THREAT_ACTOR_ROLE = [
    "agent",
    "director",
    "independent",
    "infrastructure-architect",
    "infrastructure-operator",
    "malware-author",
    "sponsor",
]


THREAT_ACTOR_SOPHISTICATION = [
    "none",
    "minimal",
    "intermediate",
    "advanced",
    "expert",
    "innovator",
    "strategic",
]


TOOL_TYPE = [
    "denial-of-service",
    "exploitation",
    "information-gathering",
    "network-capture",
    "credential-exploitation",
    "remote-access",
    "vulnerability-scanning",
    "unknown",
]


WINDOWS_INTEGRITY_LEVEL = [
    "low",
    "medium",
    "high",
    "system",
]


WINDOWS_PEBINARY_TYPE = [
    "dll",
    "exe",
    "sys",
]


WINDOWS_REGISTRY_DATATYPE = [
    "REG_NONE",
    "REG_SZ",
    "REG_EXPAND_SZ",
    "REG_BINARY",
    "REG_DWORD",
    "REG_DWORD_BIG_ENDIAN",
    "REG_DWORD_LITTLE_ENDIAN",
    "REG_LINK",
    "REG_MULTI_SZ",
    "REG_RESOURCE_LIST",
    "REG_FULL_RESOURCE_DESCRIPTION",
    "REG_RESOURCE_REQUIREMENTS_LIST",
    "REG_QWORD",
    "REG_INVALID_TYPE",
]


WINDOWS_SERVICE_START_TYPE = [
    "SERVICE_AUTO_START",
    "SERVICE_BOOT_START",
    "SERVICE_DEMAND_START",
    "SERVICE_DISABLED",
    "SERVICE_SYSTEM_ALERT",
]


WINDOWS_SERVICE_TYPE = [
    "SERVICE_KERNEL_DRIVER",
    "SERVICE_FILE_SYSTEM_DRIVER",
    "SERVICE_WIN32_OWN_PROCESS",
    "SERVICE_WIN32_SHARE_PROCESS",
]


WINDOWS_SERVICE_STATUS = [
    "SERVICE_CONTINUE_PENDING",
    "SERVICE_PAUSE_PENDING",
    "SERVICE_PAUSED",
    "SERVICE_RUNNING",
    "SERVICE_START_PENDING",
    "SERVICE_STOP_PENDING",
    "SERVICE_STOPPED",
]
