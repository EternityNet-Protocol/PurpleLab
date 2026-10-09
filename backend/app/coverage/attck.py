from typing import Any


ATTACK_TECHNIQUES: dict[str, dict[str, Any]] = {
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Command and script interpreters may be used to execute commands.",
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "PowerShell commands and scripts are used for execution.",
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion",
        "description": "Code is injected into another process to evade process-based defenses.",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Application-layer protocols are used for command and control.",
    },
    "T1071.001": {
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "description": "Web protocols may be used for command and control.",
    },
    "T1547.001": {
        "name": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "description": "Registry Run keys or startup folders may be used for persistence.",
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Credential material may be collected from operating system stores.",
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "description": "Task scheduling facilities may be abused for recurring execution.",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Tools or files may be transferred into a compromised environment.",
    },
}


def technique_info(technique_id: str) -> dict[str, Any]:
    return ATTACK_TECHNIQUES.get(
        technique_id,
        {"name": "Unknown", "tactic": "Unknown", "description": "Not in static reference set."},
    )


def list_techniques() -> list[dict[str, Any]]:
    return [{"id": key, **values} for key, values in ATTACK_TECHNIQUES.items()]