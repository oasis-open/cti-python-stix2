"""
STIX 2.0 open vocabularies and enums
"""

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


HASHING_ALGORITHM = [
    "MD5",
    "MD6",
    "RIPEMD-160",
    "SHA-1",
    "SHA-224",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    "ssdeep",
    "WHIRLPOOL",
]


IDENTITY_CLASS = [
    "individual",
    "group",
    "organization",
    "class",
    "unknown",
]


INDICATOR_LABEL = [
    "anomalous-activity",
    "anonymization",
    "benign",
    "compromised",
    "malicious-activity",
    "attribution",
]


INDUSTRY_SECTOR = [
    "agriculture",
    "aerospace",
    "automotive",
    "communications",
    "construction",
    "defence",
    "education",
    "energy",
    "entertainment",
    "financial-services",
    "government-national",
    "government-regional",
    "government-local",
    "government-public-services",
    "healthcare",
    "hospitality-leisure",
    "infrastructure",
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


MALWARE_LABEL = [
    "adware",
    "backdoor",
    "bot",
    "ddos",
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
    "virus",
    "worm",
]


REPORT_LABEL = [
    "threat-report",
    "attack-pattern",
    "campaign",
    "identity",
    "indicator",
    "intrusion-set",
    "malware",
    "observed-data",
    "threat-actor",
    "tool",
    "vulnerability",
]


THREAT_ACTOR_LABEL = [
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


TOOL_LABEL = [
    "denial-of-service",
    "exploitation",
    "information-gathering",
    "network-capture",
    "credential-exploitation",
    "remote-access",
    "vulnerability-scanning",
]
