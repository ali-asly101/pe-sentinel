"""
YARA Scanner Module
Integrates YARA rule scanning for enhanced malware detection.
"""

import os
from typing import Dict, List, Optional
from dataclasses import dataclass
from pathlib import Path

from .config import AnalysisConfig, DEFAULT_CONFIG

# Try to import yara, handle if not installed
try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


@dataclass
class YaraMatch:
    """Represents a YARA rule match"""

    rule: str
    namespace: str
    tags: List[str]
    meta: Dict
    strings: List[Dict]
    score: int


@dataclass
class YaraScanResult:
    """Complete YARA scan result"""

    available: bool
    scanned: bool
    matches: List[YaraMatch]
    total_score: int
    matched_categories: List[str]
    critical_matches: List[str]
    warnings: List[str]


class YaraScanner:
    """YARA rule-based scanner for malware detection"""

    def __init__(self, config: AnalysisConfig = None, rules_path: str = None):
        self.config = config or DEFAULT_CONFIG
        self.rules_path = rules_path or self.config.yara.rules_directory
        self.rules = None
        self._compile_rules()

    def _compile_rules(self):
        """Compile YARA rules from directory"""
        if not YARA_AVAILABLE:
            return

        rules_dir = Path(self.rules_path)
        if not rules_dir.exists():
            return

        rule_files = {}
        for yar_file in rules_dir.glob("*.yar"):
            namespace = yar_file.stem
            rule_files[namespace] = str(yar_file)

        for yar_file in rules_dir.glob("*.yara"):
            namespace = yar_file.stem
            rule_files[namespace] = str(yar_file)

        if rule_files:
            try:
                self.rules = yara.compile(filepaths=rule_files)
            except yara.Error as e:
                print(f"Warning: Failed to compile YARA rules: {e}")
                self.rules = None

    def scan(self, filepath: str) -> YaraScanResult:
        """
        Scan a file with YARA rules.

        Args:
            filepath: Path to file to scan

        Returns:
            YaraScanResult with all matches
        """
        if not YARA_AVAILABLE:
            return YaraScanResult(
                available=False,
                scanned=False,
                matches=[],
                total_score=0,
                matched_categories=[],
                critical_matches=[],
                warnings=[
                    "YARA library not installed. Install with: pip install yara-python"
                ],
            )

        if self.rules is None:
            return YaraScanResult(
                available=True,
                scanned=False,
                matches=[],
                total_score=0,
                matched_categories=[],
                critical_matches=[],
                warnings=[f"No YARA rules found in {self.rules_path}"],
            )

        try:
            raw_matches = self.rules.match(filepath, timeout=self.config.yara.timeout)
        except yara.Error as e:
            return YaraScanResult(
                available=True,
                scanned=False,
                matches=[],
                total_score=0,
                matched_categories=[],
                critical_matches=[],
                warnings=[f"YARA scan error: {e}"],
            )

        # Process matches
        matches = []
        total_score = 0
        categories = set()
        critical_matches = []
        category_scores = self.config.yara.category_scores

        for match in raw_matches:
            # Determine score based on namespace/tags
            score = 10  # Default score

            # Check namespace
            if match.namespace in category_scores:
                score = category_scores[match.namespace]

            # Check tags for category
            for tag in match.tags:
                tag_lower = tag.lower()
                if tag_lower in category_scores:
                    score = max(score, category_scores[tag_lower])
                categories.add(tag_lower)

            # Check meta for severity
            meta = dict(match.meta) if match.meta else {}
            if meta.get("severity") == "critical":
                score = max(score, 50)
                critical_matches.append(match.rule)
            elif meta.get("severity") == "high":
                score = max(score, 40)

            # Extract matched strings (limit for large matches)
            string_matches = []
            for string_match in match.strings[:10]:  # Limit to 10 strings
                string_matches.append(
                    {
                        "identifier": string_match[1] if len(string_match) > 1 else "",
                        "offset": string_match[0] if len(string_match) > 0 else 0,
                        "data": (
                            str(string_match[2])[:50] if len(string_match) > 2 else ""
                        ),
                    }
                )

            matches.append(
                YaraMatch(
                    rule=match.rule,
                    namespace=match.namespace,
                    tags=list(match.tags),
                    meta=meta,
                    strings=string_matches,
                    score=score,
                )
            )

            total_score += score

        # Generate warnings
        warnings = []
        if critical_matches:
            warnings.append(
                f"🔴 CRITICAL: {len(critical_matches)} critical YARA matches"
            )

        if "ransomware" in categories:
            warnings.append("🔴 Ransomware signatures detected")

        if "rat" in categories or "backdoor" in categories:
            warnings.append("🔴 RAT/Backdoor signatures detected")

        return YaraScanResult(
            available=True,
            scanned=True,
            matches=matches,
            total_score=min(100, total_score),  # Cap at 100
            matched_categories=list(categories),
            critical_matches=critical_matches,
            warnings=warnings,
        )

    def scan_data(self, data: bytes) -> YaraScanResult:
        """
        Scan raw data with YARA rules.

        Args:
            data: Raw bytes to scan

        Returns:
            YaraScanResult with all matches
        """
        if not YARA_AVAILABLE or self.rules is None:
            return YaraScanResult(
                available=YARA_AVAILABLE,
                scanned=False,
                matches=[],
                total_score=0,
                matched_categories=[],
                critical_matches=[],
                warnings=["YARA not available or no rules loaded"],
            )

        try:
            raw_matches = self.rules.match(data=data, timeout=self.config.yara.timeout)
        except yara.Error as e:
            return YaraScanResult(
                available=True,
                scanned=False,
                matches=[],
                total_score=0,
                matched_categories=[],
                critical_matches=[],
                warnings=[f"YARA scan error: {e}"],
            )

        # Process matches (same as file scan)
        # ... (simplified for brevity)
        matches = []
        total_score = 0

        for match in raw_matches:
            score = self.config.yara.category_scores.get(match.namespace, 10)
            matches.append(
                YaraMatch(
                    rule=match.rule,
                    namespace=match.namespace,
                    tags=list(match.tags),
                    meta=dict(match.meta) if match.meta else {},
                    strings=[],
                    score=score,
                )
            )
            total_score += score

        return YaraScanResult(
            available=True,
            scanned=True,
            matches=matches,
            total_score=min(100, total_score),
            matched_categories=list(set(m.namespace for m in matches)),
            critical_matches=[],
            warnings=[],
        )


# Sample YARA rules for testing
SAMPLE_RULES = """
rule Suspicious_Strings {
    meta:
        description = "Detects common suspicious strings"
        severity = "medium"
    strings:
        $s1 = "cmd.exe /c" nocase
        $s2 = "powershell -enc" nocase
        $s3 = "VirtualAlloc" 
        $s4 = "WriteProcessMemory"
        $s5 = "CreateRemoteThread"
    condition:
        3 of them
}

rule Potential_Ransomware {
    meta:
        description = "Potential ransomware indicators"
        severity = "critical"
    strings:
        $s1 = "vssadmin delete" nocase
        $s2 = "bcdedit /set" nocase
        $s3 = "wmic shadowcopy" nocase
        $s4 = ".locked" nocase
        $s5 = "your files have been encrypted" nocase
        $s6 = "bitcoin" nocase
    condition:
        2 of them
}

rule UPX_Packed {
    meta:
        description = "UPX packed executable"
        severity = "low"
    strings:
        $upx1 = "UPX0" 
        $upx2 = "UPX1"
        $upx3 = "UPX!"
    condition:
        any of them
}

rule Keylogger_Indicators {
    meta:
        description = "Keylogger behavior indicators"
        severity = "high"
    strings:
        $s1 = "GetAsyncKeyState" 
        $s2 = "SetWindowsHookEx"
        $s3 = "GetKeyboardState"
        $s4 = "keylog" nocase
    condition:
        2 of them
}

rule Network_Backdoor {
    meta:
        description = "Network backdoor indicators"
        severity = "high"
    strings:
        $s1 = "WSAStartup"
        $s2 = "connect"
        $s3 = "recv"
        $s4 = "send"
        $s5 = "cmd.exe" nocase
        $s6 = "shell" nocase
    condition:
        4 of them
}
"""


def create_sample_rules(rules_dir: str = "rules"):
    """Create sample YARA rules for testing"""
    rules_path = Path(rules_dir)
    rules_path.mkdir(exist_ok=True)

    sample_file = rules_path / "sample_rules.yar"
    with open(sample_file, "w") as f:
        f.write(SAMPLE_RULES)

    print(f"Created sample YARA rules at: {sample_file}")
    return str(sample_file)
