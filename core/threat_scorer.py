"""
Threat scoring and suspicious API detection
"""

from typing import List, Dict, Tuple


class ThreatScorer:
    """Calculate threat score based on multiple indicators"""

    SUSPICIOUS_APIS = {
        # Code Injection
        "CreateRemoteThread": "Code Injection",
        "WriteProcessMemory": "Process Injection",
        "VirtualAllocEx": "Memory Manipulation",
        "SetWindowsHookEx": "Hooking/Keylogging",
        "NtQueueApcThread": "APC Injection",
        # Persistence
        "RegSetValueEx": "Registry Modification",
        "RegCreateKeyEx": "Registry Modification",
        "CreateServiceA": "Service Creation",
        "CreateServiceW": "Service Creation",
        # Evasion
        "IsDebuggerPresent": "Anti-Debugging",
        "CheckRemoteDebuggerPresent": "Anti-Debugging",
        "NtQueryInformationProcess": "Anti-Analysis",
        "GetTickCount": "Timing Check (Anti-VM)",
        # Network
        "WSAStartup": "Network Activity",
        "InternetOpenA": "HTTP Communication",
        "InternetOpenUrlA": "URL Access",
        "socket": "Network Socket",
        # Crypto
        "CryptEncrypt": "Encryption",
        "CryptAcquireContext": "Crypto Operations",
        # File Operations
        "CreateFileA": "File Access",
        "CreateFileW": "File Access",
        "DeleteFileA": "File Deletion",
        "DeleteFileW": "File Deletion",
    }

    def __init__(
        self,
        sections: List[Dict],
        imports: List[Dict],
        is_signed: bool,
        packers: List[str],
    ):
        self.sections = sections
        self.imports = imports
        self.is_signed = is_signed
        self.packers = packers

    def calculate_score(self) -> Tuple[int, List[str]]:
        """Calculate threat score (0-100) with reasons"""
        score = 0
        reasons = []

        # 1. Packer detection (20 points)
        if self.packers:
            score += 20
            reasons.append(f"Packers detected: {', '.join(self.packers)} (+20)")

        # 2. High entropy sections (15 points)
        from .analyzers import EntropyAnalyzer

        for section in self.sections:
            entropy = EntropyAnalyzer.calculate(section["data"])
            if entropy > 7.5:
                score += 15
                reasons.append(
                    f"High entropy in {section['name']}: {entropy:.2f} (+15)"
                )
                break

        # 3. W+X sections (25 points)
        for section in self.sections:
            if "W" in section["permissions"] and "X" in section["permissions"]:
                score += 25
                reasons.append(f"W+X permissions in {section['name']} (+25)")
                break

        # 4. Suspicious APIs (up to 30 points)
        suspicious_count = self._count_suspicious_apis()
        if suspicious_count > 10:
            score += 30
            reasons.append(f"{suspicious_count} suspicious APIs (+30)")
        elif suspicious_count > 5:
            score += 20
            reasons.append(f"{suspicious_count} suspicious APIs (+20)")
        elif suspicious_count > 0:
            score += 10
            reasons.append(f"{suspicious_count} suspicious APIs (+10)")

        # 5. Unsigned binary (10 points)
        if not self.is_signed:
            score += 10
            reasons.append("Unsigned binary (+10)")

        return min(100, score), reasons

    def get_suspicious_imports(self) -> List[Dict]:
        """Get list of suspicious API calls"""
        suspicious = []

        for dll_entry in self.imports:
            for func in dll_entry["functions"]:
                if func["name"] in self.SUSPICIOUS_APIS:
                    suspicious.append(
                        {
                            "dll": dll_entry["dll"],
                            "function": func["name"],
                            "reason": self.SUSPICIOUS_APIS[func["name"]],
                        }
                    )

        return suspicious

    def _count_suspicious_apis(self) -> int:
        """Count total suspicious API calls"""
        return len(self.get_suspicious_imports())

    def get_threat_level(self, score: int) -> str:
        """Convert score to threat level"""
        if score >= 70:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        else:
            return "LOW"
