"""
Phase 2: Correlation & Harmony
Correlates API capabilities with structural obfuscation.
Reuses SectionAnalyzer results from analyzers.py
"""

from typing import Dict, List, Tuple


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
            ],
            "min_match": 3,
            "base_score": 40,
            "description": "Process Injection Capability",
        },
        "spyware": {
            "apis": ["SetWindowsHookEx", "GetAsyncKeyState", "GetClipboardData"],
            "min_match": 2,
            "base_score": 35,
            "description": "Keystroke/Clipboard Monitoring",
        },
        "dropper": {
            "apis": [
                "URLDownloadToFile",
                "URLDownloadToFileA",
                "InternetOpenUrl",
                "CreateProcess",
                "WinExec",
                "ShellExecute",
            ],
            "min_match": 2,
            "base_score": 30,
            "description": "Download & Execute Capability",
        },
        "ransomware": {
            "apis": [
                "CryptEncrypt",
                "CryptAcquireContext",
                "FindFirstFile",
                "FindFirstFileA",
                "DeleteFile",
                "DeleteFileA",
            ],
            "min_match": 3,
            "base_score": 50,
            "description": "File Encryption Capability",
        },
        "persistence": {
            "apis": [
                "RegSetValueEx",
                "RegSetValueExA",
                "RegCreateKeyEx",
                "CreateService",
                "CreateServiceA",
                "CreateServiceW",
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
                "EnumProcesses",
                "TerminateProcess",
            ],
            "min_match": 2,
            "base_score": 35,
            "description": "Anti-Analysis/AV Termination",
        },
        "credential_theft": {
            "apis": [
                "CredEnumerate",
                "CredEnumerateA",
                "CryptUnprotectData",
                "LsaEnumerateLogonSessions",
            ],
            "min_match": 1,
            "base_score": 40,
            "description": "Credential Dumping",
        },
        "code_execution": {
            "apis": [
                "CreateThread",
                "VirtualAlloc",
                "VirtualProtect",
                "WriteProcessMemory",
            ],
            "min_match": 3,
            "base_score": 30,
            "description": "Dynamic Code Execution",
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
                detected_capabilities.append(
                    {
                        "capability": capability_name,
                        "description": cluster["description"],
                        "base_score": cluster["base_score"],
                        "matched_apis": list(matched_apis),
                        "match_count": len(matched_apis),
                        "required_count": cluster["min_match"],
                    }
                )

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

    @staticmethod
    def calculate_obfuscation_multiplier(
        section_analyses: List,
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

        for analysis in section_analyses:
            # Check for high expansion ratio
            if analysis.size_ratio > 2.0:
                multiplier = max(multiplier, 2.0)
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
            if analysis.entropy > 7.5:
                multiplier = max(multiplier, 1.8)
                reasons.append(
                    f"Section {analysis.name}: Very high entropy ({analysis.entropy:.2f}) indicates encryption"
                )

        # Cap multiplier at 3.0x
        multiplier = min(3.0, multiplier)

        return multiplier, reasons


class CorrelationEngine:
    """Harmonize capabilities with obfuscation indicators"""

    @staticmethod
    def correlate(features: Dict, section_analyses: List) -> Dict:
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
            ObfuscationAnalyzer.calculate_obfuscation_multiplier(section_analyses)
        )

        # Apply multiplier to each capability
        scored_capabilities = []
        total_capability_score = 0

        for cap in capabilities["detected_capabilities"]:
            base_score = cap["base_score"]
            final_score = int(base_score * obfuscation_mult)

            scored_capabilities.append(
                {
                    **cap,
                    "obfuscation_multiplier": obfuscation_mult,
                    "final_score": final_score,
                    "is_obfuscated": obfuscation_mult > 1.0,
                }
            )

            total_capability_score += final_score

        return {
            "capabilities": scored_capabilities,
            "total_capability_score": min(80, total_capability_score),  # Cap at 80
            "obfuscation_multiplier": obfuscation_mult,
            "obfuscation_reasons": obfuscation_reasons,
            "is_obfuscated": obfuscation_mult > 1.0,
        }
