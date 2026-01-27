"""
Phase 2: Correlation & Harmony
Correlates API capabilities with structural obfuscation.
Reuses SectionAnalyzer results from analyzers.py
"""

from typing import Dict, List, Tuple

from ..config import AnalysisConfig, DEFAULT_CONFIG
from ..analyzers import SectionAnalysis


class FunctionalClusterer:
    """Group APIs into functional capabilities"""

    # Define capability clusters
    CAPABILITY_CLUSTERS = {
        "injection": {
            "apis": [
                "OpenProcess",
                "VirtualAllocEx",
                "WriteProcessMemory",
                "CreateRemoteThread",
                "NtCreateThreadEx",
                "RtlCreateUserThread",
                "QueueUserAPC",
                "NtQueueApcThread",
            ],
            "min_match": 3,
            "base_score": 40,
            "description": "Process Injection Capability",
        },
        "hollowing": {
            "apis": [
                "NtUnmapViewOfSection",
                "ZwUnmapViewOfSection",
                "NtMapViewOfSection",
                "CreateProcess",
                "WriteProcessMemory",
                "SetThreadContext",
                "ResumeThread",
            ],
            "min_match": 4,
            "base_score": 45,
            "description": "Process Hollowing",
        },
        "spyware": {
            "apis": [
                "SetWindowsHookEx",
                "SetWindowsHookExA",
                "SetWindowsHookExW",
                "GetAsyncKeyState",
                "GetKeyState",
                "GetClipboardData",
                "RegisterRawInputDevices",
            ],
            "min_match": 2,
            "base_score": 35,
            "description": "Keystroke/Clipboard Monitoring",
        },
        "dropper": {
            "apis": [
                "URLDownloadToFile",
                "URLDownloadToFileA",
                "URLDownloadToFileW",
                "InternetOpenUrl",
                "InternetOpenUrlA",
                "InternetReadFile",
                "HttpOpenRequest",
                "WinHttpOpen",
                "CreateProcess",
                "CreateProcessA",
                "CreateProcessW",
                "WinExec",
                "ShellExecute",
                "ShellExecuteA",
                "ShellExecuteW",
            ],
            "min_match": 2,
            "base_score": 30,
            "description": "Download & Execute Capability",
        },
        "ransomware": {
            "apis": [
                "CryptEncrypt",
                "CryptAcquireContext",
                "CryptAcquireContextA",
                "CryptAcquireContextW",
                "CryptGenKey",
                "CryptImportKey",
                "CryptExportKey",
                "BCryptEncrypt",
                "FindFirstFile",
                "FindFirstFileA",
                "FindFirstFileW",
                "FindNextFile",
                "DeleteFile",
                "DeleteFileA",
                "DeleteFileW",
                "MoveFile",
                "MoveFileEx",
            ],
            "min_match": 4,
            "base_score": 50,
            "description": "File Encryption Capability",
        },
        "persistence": {
            "apis": [
                "RegSetValueEx",
                "RegSetValueExA",
                "RegSetValueExW",
                "RegCreateKeyEx",
                "RegCreateKeyExA",
                "RegCreateKeyExW",
                "CreateService",
                "CreateServiceA",
                "CreateServiceW",
                "ChangeServiceConfig",
                "RegSetKeyValue",
            ],
            "min_match": 1,
            "base_score": 25,
            "description": "Persistence Mechanism",
        },
        "av_evasion": {
            "apis": [
                "IsDebuggerPresent",
                "CheckRemoteDebuggerPresent",
                "NtQueryInformationProcess",
                "NtSetInformationThread",
                "EnumProcesses",
                "CreateToolhelp32Snapshot",
                "Process32First",
                "Process32Next",
                "TerminateProcess",
                "OutputDebugString",
            ],
            "min_match": 2,
            "base_score": 35,
            "description": "Anti-Analysis/AV Evasion",
        },
        "credential_theft": {
            "apis": [
                "CredEnumerate",
                "CredEnumerateA",
                "CredEnumerateW",
                "CryptUnprotectData",
                "LsaEnumerateLogonSessions",
                "LsaGetLogonSessionData",
                "SamEnumerateUsersInDomain",
                "NetUserEnum",
            ],
            "min_match": 1,
            "base_score": 40,
            "description": "Credential Dumping",
        },
        "code_execution": {
            "apis": [
                "CreateThread",
                "VirtualAlloc",
                "VirtualAllocEx",
                "VirtualProtect",
                "VirtualProtectEx",
                "WriteProcessMemory",
                "NtAllocateVirtualMemory",
                "NtProtectVirtualMemory",
            ],
            "min_match": 3,
            "base_score": 30,
            "description": "Dynamic Code Execution",
        },
        "privilege_escalation": {
            "apis": [
                "AdjustTokenPrivileges",
                "OpenProcessToken",
                "LookupPrivilegeValue",
                "ImpersonateLoggedOnUser",
                "DuplicateToken",
                "DuplicateTokenEx",
                "SetThreadToken",
            ],
            "min_match": 2,
            "base_score": 35,
            "description": "Privilege Escalation",
        },
        "defense_evasion": {
            "apis": [
                "NtSetInformationFile",
                "SetFileAttributes",
                "SetFileAttributesA",
                "DeleteFile",
                "ZwDeleteFile",
                "NtDeleteFile",
                "MoveFileEx",  # With MOVEFILE_DELAY_UNTIL_REBOOT
            ],
            "min_match": 2,
            "base_score": 25,
            "description": "Defense Evasion/Cleanup",
        },
        "screen_capture": {
            "apis": [
                "GetDC",
                "GetWindowDC",
                "BitBlt",
                "CreateCompatibleDC",
                "CreateCompatibleBitmap",
                "GetDIBits",
            ],
            "min_match": 4,
            "base_score": 30,
            "description": "Screen Capture Capability",
        },
    }

    @classmethod
    def detect_capabilities(cls, iat_features: Dict) -> Dict:
        """
        Detect functional capabilities based on imported APIs.
        Returns detected clusters WITHOUT scoring (that's Phase 3's job).
        """
        all_apis = iat_features.get("all_functions", set())

        detected_capabilities = []

        for capability_name, cluster in cls.CAPABILITY_CLUSTERS.items():
            required_apis = set(cluster["apis"])
            matched_apis = required_apis & all_apis

            if len(matched_apis) >= cluster["min_match"]:
                # Calculate confidence based on how many APIs matched
                confidence = len(matched_apis) / len(required_apis)

                detected_capabilities.append(
                    {
                        "capability": capability_name,
                        "description": cluster["description"],
                        "base_score": cluster["base_score"],
                        "matched_apis": list(matched_apis),
                        "match_count": len(matched_apis),
                        "required_count": cluster["min_match"],
                        "total_apis": len(required_apis),
                        "confidence": confidence,
                    }
                )

        # Sort by confidence then by base_score
        detected_capabilities.sort(key=lambda x: (-x["confidence"], -x["base_score"]))

        return {
            "detected_capabilities": detected_capabilities,
            "capability_count": len(detected_capabilities),
            "total_unique_apis": len(all_apis),
        }


class ObfuscationAnalyzer:
    """
    Analyze if code is being hidden.
    REUSES SectionAnalyzer results from analyzers.py
    """

    def __init__(self, config: AnalysisConfig = None):
        self.config = config or DEFAULT_CONFIG

    def calculate_obfuscation_multiplier(
        self,
        section_analyses: List[SectionAnalysis],
    ) -> Tuple[float, List[str]]:
        """
        Calculate multiplier based on obfuscation indicators.

        Rule: If (Expansion > 2.0 OR Entropy Spike), multiply threat by 2.0x

        Args:
            section_analyses: List of SectionAnalysis objects from analyzers.py

        Returns:
            (multiplier, reasons)
        """
        multiplier = 1.0
        reasons = []
        cfg = self.config

        for analysis in section_analyses:
            # Check for high expansion ratio
            if analysis.size_ratio > cfg.size.expansion_ratio_moderate:
                mult_increase = min(2.0, 1.0 + (analysis.size_ratio - 1.0) * 0.3)
                if mult_increase > multiplier:
                    multiplier = mult_increase
                    reasons.append(
                        f"Section {analysis.name}: {analysis.size_ratio:.1f}x expansion indicates packing"
                    )

            # Check for entropy spikes (segment anomalies)
            if analysis.segment_analysis.get("has_anomaly", False):
                multiplier = max(multiplier, 1.5)
                reasons.append(
                    f"Section {analysis.name}: {analysis.segment_analysis['anomaly_reason']}"
                )

            # Check for very high overall entropy
            if analysis.entropy > cfg.entropy.critical:
                multiplier = max(multiplier, 1.8)
                reasons.append(
                    f"Section {analysis.name}: Very high entropy ({analysis.entropy:.2f}) indicates encryption"
                )

            # Check for W+X permissions (self-modifying code)
            if "W" in analysis.permissions and "X" in analysis.permissions:
                multiplier = max(multiplier, 1.3)
                reasons.append(
                    f"Section {analysis.name}: W+X permissions (self-modifying code)"
                )

        # Cap multiplier
        max_mult = cfg.scoring.max_obfuscation_multiplier
        multiplier = min(max_mult, multiplier)

        return multiplier, reasons


class CorrelationEngine:
    """Harmonize capabilities with obfuscation indicators"""

    def __init__(self, config: AnalysisConfig = None):
        self.config = config or DEFAULT_CONFIG
        self.obfuscation_analyzer = ObfuscationAnalyzer(config)

    def correlate(
        self, features: Dict, section_analyses: List[SectionAnalysis]
    ) -> Dict:
        """
        Correlate functional capabilities with structural obfuscation.

        Logic: Dangerous capability + Hidden = HIGH THREAT
               Dangerous capability + Visible = MEDIUM THREAT

        Args:
            features: From FeatureExtractor (IAT, trust, UI)
            section_analyses: List of SectionAnalysis from analyzers.py
        """
        # Detect capabilities
        capabilities = FunctionalClusterer.detect_capabilities(features["iat_analysis"])

        # Calculate obfuscation multiplier using EXISTING section analysis
        obfuscation_mult, obfuscation_reasons = (
            self.obfuscation_analyzer.calculate_obfuscation_multiplier(section_analyses)
        )

        # Apply multiplier to each capability
        scored_capabilities = []
        total_capability_score = 0

        for cap in capabilities["detected_capabilities"]:
            base_score = cap["base_score"]

            # Apply confidence adjustment
            confidence_adjusted = int(base_score * (0.7 + 0.3 * cap["confidence"]))

            # Apply obfuscation multiplier
            final_score = int(confidence_adjusted * obfuscation_mult)

            scored_capabilities.append(
                {
                    **cap,
                    "confidence_adjusted_score": confidence_adjusted,
                    "obfuscation_multiplier": obfuscation_mult,
                    "final_score": final_score,
                    "is_obfuscated": obfuscation_mult > 1.0,
                }
            )

            total_capability_score += final_score

        # Cap total score
        max_cap_score = self.config.scoring.max_capability_score

        return {
            "capabilities": scored_capabilities,
            "total_capability_score": min(max_cap_score, total_capability_score),
            "raw_capability_score": total_capability_score,
            "obfuscation_multiplier": obfuscation_mult,
            "obfuscation_reasons": obfuscation_reasons,
            "is_obfuscated": obfuscation_mult > 1.0,
            "capability_summary": self._summarize_capabilities(scored_capabilities),
        }

    def _summarize_capabilities(self, capabilities: List[Dict]) -> Dict:
        """Generate a summary of detected capabilities"""
        if not capabilities:
            return {
                "threat_categories": [],
                "highest_threat": None,
                "total_capabilities": 0,
            }

        # Categorize by threat type
        categories = {
            "data_theft": ["spyware", "credential_theft", "screen_capture"],
            "code_execution": ["injection", "hollowing", "code_execution"],
            "persistence": ["persistence"],
            "evasion": ["av_evasion", "defense_evasion"],
            "ransomware": ["ransomware"],
            "delivery": ["dropper"],
            "privilege": ["privilege_escalation"],
        }

        detected_categories = []
        for category, cap_names in categories.items():
            if any(c["capability"] in cap_names for c in capabilities):
                detected_categories.append(category)

        # Find highest threat capability
        highest = max(capabilities, key=lambda x: x["final_score"])

        return {
            "threat_categories": detected_categories,
            "highest_threat": highest["description"],
            "highest_score": highest["final_score"],
            "total_capabilities": len(capabilities),
        }
