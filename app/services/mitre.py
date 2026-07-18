from __future__ import annotations

MITRE_TECHNIQUES = {
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion / Persistence"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1136.001": {"name": "Local Account", "tactic": "Persistence"},
    "T1070.001": {"name": "Clear Windows Event Logs", "tactic": "Defense Evasion"},
    "T1543.003": {"name": "Windows Service", "tactic": "Persistence / Privilege Escalation"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1087": {"name": "Account Discovery", "tactic": "Discovery"},
    "T1562.001": {"name": "Impair Defenses", "tactic": "Defense Evasion"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Execution / Persistence"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
}

TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


def technique_info(technique_id: str | None) -> dict[str, str]:
    if not technique_id:
        return {"name": "Unmapped", "tactic": "Unmapped"}
    return MITRE_TECHNIQUES.get(technique_id, {"name": "Custom Mapping", "tactic": "Unmapped"})
