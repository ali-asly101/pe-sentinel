"""
MITRE ATT&CK Technique Mapper
Maps detected API patterns to MITRE ATT&CK tactics and techniques
"""

from typing import Dict, List, Set


class MitreMapper:
    """Map malicious capabilities to MITRE ATT&CK framework"""

    # MITRE ATT&CK Technique Mappings
    TECHNIQUE_MAPPINGS = {
        "injection": {
            "technique_id": "T1055",
            "technique_name": "Process Injection",
            "tactic": "Defense Evasion",
            "description": "Inject code into processes to evade detection",
            "apis": [
                "OpenProcess",
                "VirtualAllocEx",
                "WriteProcessMemory",
                "CreateRemoteThread",
            ],
        },
        "spyware": {
            "technique_id": "T1056.001",
            "technique_name": "Input Capture: Keylogging",
            "tactic": "Collection",
            "description": "Capture user keystrokes",
            "apis": ["SetWindowsHookEx", "GetAsyncKeyState", "GetClipboardData"],
        },
        "dropper": {
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
            "description": "Download and execute additional payloads",
            "apis": ["URLDownloadToFile", "InternetOpenUrl", "CreateProcess"],
        },
        "ransomware": {
            "technique_id": "T1486",
            "technique_name": "Data Encrypted for Impact",
            "tactic": "Impact",
            "description": "Encrypt files to extort victims",
            "apis": [
                "CryptEncrypt",
                "CryptAcquireContext",
                "FindFirstFile",
                "DeleteFile",
            ],
        },
        "persistence": {
            "technique_id": "T1547.001",
            "technique_name": "Registry Run Keys / Startup Folder",
            "tactic": "Persistence",
            "description": "Maintain persistence via registry or startup",
            "apis": ["RegSetValueEx", "RegCreateKeyEx", "CreateService"],
        },
        "av_evasion": {
            "technique_id": "T1622",
            "technique_name": "Debugger Evasion",
            "tactic": "Defense Evasion",
            "description": "Detect and evade debugging/analysis",
            "apis": [
                "IsDebuggerPresent",
                "CheckRemoteDebuggerPresent",
                "NtQueryInformationProcess",
            ],
        },
        "credential_theft": {
            "technique_id": "T1555",
            "technique_name": "Credentials from Password Stores",
            "tactic": "Credential Access",
            "description": "Extract credentials from system stores",
            "apis": [
                "CredEnumerate",
                "CryptUnprotectData",
                "LsaEnumerateLogonSessions",
            ],
        },
        "code_execution": {
            "technique_id": "T1106",
            "technique_name": "Native API",
            "tactic": "Execution",
            "description": "Execute code via native Windows APIs",
            "apis": ["CreateThread", "VirtualAlloc", "VirtualProtect"],
        },
    }

    @classmethod
    def map_capabilities(cls, capabilities: List[Dict]) -> List[Dict]:
        """
        Map detected capabilities to MITRE ATT&CK techniques

        Args:
            capabilities: List of detected capabilities from CorrelationEngine

        Returns:
            List of MITRE techniques with metadata
        """
        techniques = []
        seen_techniques = set()

        for cap in capabilities:
            capability_type = cap["capability"]

            if capability_type in cls.TECHNIQUE_MAPPINGS:
                technique = cls.TECHNIQUE_MAPPINGS[capability_type]
                technique_id = technique["technique_id"]

                # Avoid duplicates
                if technique_id not in seen_techniques:
                    techniques.append(
                        {
                            "id": technique_id,
                            "name": technique["technique_name"],
                            "tactic": technique["tactic"],
                            "description": technique["description"],
                            "matched_apis": cap["matched_apis"],
                            "confidence": (
                                "High" if cap["match_count"] >= 3 else "Medium"
                            ),
                            "url": f'https://attack.mitre.org/techniques/{technique_id.replace(".", "/")}/',
                        }
                    )
                    seen_techniques.add(technique_id)

        return techniques

    @classmethod
    def generate_attack_matrix(cls, techniques: List[Dict]) -> Dict:
        """
        Generate MITRE ATT&CK matrix view

        Returns tactics and their associated techniques
        """
        matrix = {}

        for technique in techniques:
            tactic = technique["tactic"]
            if tactic not in matrix:
                matrix[tactic] = []
            matrix[tactic].append(technique)

        return matrix
