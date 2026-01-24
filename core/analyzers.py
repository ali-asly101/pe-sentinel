"""
Various analysis functions: entropy, packer detection, strings, etc.
"""

import math
from typing import List, Dict


class EntropyAnalyzer:
    """Shannon entropy calculation and classification"""

    @staticmethod
    def calculate(data: bytes) -> float:
        """Calculate Shannon entropy (0.0 to 8.0)"""
        if not data:
            return 0.0

        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)

        return entropy

    @staticmethod
    def classify(entropy: float, section_name: str) -> str:
        """Classify entropy based on section context"""
        if section_name == ".text":
            if entropy > 6.8:
                return "High Entropy (Possible Obfuscation/Packing)"
            elif entropy < 4.0:
                return "Low Entropy (Sparse Code/Debugging)"
            else:
                return "Normal Code"

        elif section_name in [".data", ".rdata"]:
            if entropy > 7.5:
                return "ENCRYPTED/COMPRESSED DATA"
            elif entropy < 2.0:
                return "Mostly Zeros/Padding"
            else:
                return "Normal Data"

        elif section_name == ".rsrc":
            if entropy > 7.8:
                return "High (May Contain Compressed Resources)"
            else:
                return "Normal Resources"

        else:
            if entropy > 7.2:
                return "PACKED/ENCRYPTED"
            elif entropy < 1.0:
                return "EMPTY/PADDING"
            else:
                return "Normal"


class PackerDetector:
    """Detect common packers and obfuscation"""

    KNOWN_PACKERS = {
        "UPX": ["UPX0", "UPX1", "UPX2"],
        "ASPack": [".aspack", ".adata"],
        "PECompact": ["PEC2", "PECompact2"],
        "Themida": [".themida"],
        "VMProtect": [".vmp0", ".vmp1"],
    }

    @classmethod
    def detect_upx(cls, sections: List[Dict]) -> bool:
        """Check for UPX packer"""
        for section in sections:
            if "UPX" in section["name"].upper():
                return True
        return False

    @classmethod
    def detect_known_packers(cls, sections: List[Dict]) -> List[str]:
        """Detect known packers by section names"""
        detected = []

        for packer, signatures in cls.KNOWN_PACKERS.items():
            for section in sections:
                if any(sig.lower() in section["name"].lower() for sig in signatures):
                    detected.append(packer)
                    break

        return detected

    @staticmethod
    def detect_stealth_packing(sections: List[Dict]) -> List[str]:
        """Detect stealth packing techniques"""
        warnings = []

        for section in sections:
            # Virtual size much larger than raw size
            if section["virtual_size"] > (section["raw_size"] * 3):
                warnings.append(
                    f"Section {section['name']} expands significantly in RAM "
                    f"(VSize: {section['virtual_size']}, RawSize: {section['raw_size']})"
                )

        return warnings


class StringExtractor:
    """Extract printable strings from binary data"""

    @staticmethod
    def extract_ascii(data: bytes, min_length: int = 4) -> List[str]:
        """Extract ASCII strings"""
        strings = []
        current = ""

        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current += chr(byte)
            else:
                if len(current) >= min_length:
                    strings.append(current)
                current = ""

        # Don't forget last string
        if len(current) >= min_length:
            strings.append(current)

        return strings

    @staticmethod
    def extract_unicode(data: bytes, min_length: int = 4) -> List[str]:
        """Extract Unicode (UTF-16LE) strings"""
        strings = []
        current = ""

        for i in range(0, len(data) - 1, 2):
            if data[i + 1] == 0 and 32 <= data[i] <= 126:
                current += chr(data[i])
            else:
                if len(current) >= min_length:
                    strings.append(current)
                current = ""

        if len(current) >= min_length:
            strings.append(current)

        return strings


from typing import List, Tuple
import statistics


class SegmentEntropyAnalyzer:
    """
    Detect entropy anomalies within sections by analyzing chunks.
    Catches padding-based evasion techniques.
    """

    @staticmethod
    def analyze_segments(data: bytes, chunk_size: int = 4096) -> Dict:
        """
        Break section into chunks and analyze entropy distribution.

        Args:
            data: Section data bytes
            chunk_size: Size of each chunk (default 4KB)

        Returns:
            Dictionary with entropy statistics and anomaly flags
        """
        if len(data) < chunk_size:
            # Section too small, analyze as whole
            return {
                "chunk_count": 1,
                "entropies": [EntropyAnalyzer.calculate(data)],
                "mean": EntropyAnalyzer.calculate(data),
                "stddev": 0.0,
                "max": EntropyAnalyzer.calculate(data),
                "min": EntropyAnalyzer.calculate(data),
                "variance": 0.0,
                "has_anomaly": False,
                "anomaly_reason": None,
            }

        # Calculate entropy for each chunk
        entropies = []
        for i in range(0, len(data), chunk_size):
            chunk = data[i : i + chunk_size]
            if len(chunk) >= 256:  # Need enough data for meaningful entropy
                entropy = EntropyAnalyzer.calculate(chunk)
                entropies.append(entropy)

        if len(entropies) < 2:
            return {
                "chunk_count": len(entropies),
                "entropies": entropies,
                "mean": entropies[0] if entropies else 0,
                "stddev": 0.0,
                "max": entropies[0] if entropies else 0,
                "min": entropies[0] if entropies else 0,
                "variance": 0.0,
                "has_anomaly": False,
                "anomaly_reason": None,
            }

        # Statistical analysis
        mean_entropy = statistics.mean(entropies)
        stddev_entropy = statistics.stdev(entropies)
        max_entropy = max(entropies)
        min_entropy = min(entropies)
        variance = max_entropy - min_entropy

        # Detect anomalies
        has_anomaly, reason = SegmentEntropyAnalyzer._detect_anomaly(
            entropies, mean_entropy, stddev_entropy, variance
        )

        return {
            "chunk_count": len(entropies),
            "entropies": entropies,
            "mean": mean_entropy,
            "stddev": stddev_entropy,
            "max": max_entropy,
            "min": min_entropy,
            "variance": variance,
            "has_anomaly": has_anomaly,
            "anomaly_reason": reason,
            "chunk_size_kb": chunk_size / 1024,
        }

    @staticmethod
    def _detect_anomaly(
        entropies: List[float], mean: float, stddev: float, variance: float
    ) -> Tuple[bool, str]:
        """
        Detect if entropy distribution indicates padding/packing evasion.

        Detection patterns:
        1. High variance (mix of high and low entropy chunks)
        2. Bimodal distribution (packed code + padding)
        3. Outlier chunks (some very high, some very low)
        """

        # Pattern 1: High variance (>3.0 difference between max and min)
        if variance > 3.0:
            high_chunks = [e for e in entropies if e > 7.0]
            low_chunks = [e for e in entropies if e < 2.0]

            if high_chunks and low_chunks:
                return True, (
                    f"PADDING EVASION DETECTED: {len(high_chunks)} high-entropy chunks "
                    f"(packed code) mixed with {len(low_chunks)} low-entropy chunks (padding)"
                )

        # Pattern 2: Bimodal distribution
        # Check if we have distinct clusters of high and low entropy
        high_entropy_count = sum(1 for e in entropies if e > 6.5)
        low_entropy_count = sum(1 for e in entropies if e < 2.0)
        total = len(entropies)

        if high_entropy_count > 0 and low_entropy_count > 0:
            if (high_entropy_count + low_entropy_count) / total > 0.7:
                return True, (
                    f"BIMODAL DISTRIBUTION: {high_entropy_count} packed chunks + "
                    f"{low_entropy_count} padding chunks (evasion technique)"
                )

        # Pattern 3: First chunk(s) very high, rest very low
        # This is classic "packed code at start + padding at end"
        if len(entropies) >= 3:
            first_third = entropies[: len(entropies) // 3]
            last_third = entropies[-len(entropies) // 3 :]

            avg_first = statistics.mean(first_third)
            avg_last = statistics.mean(last_third)

            if avg_first > 7.0 and avg_last < 2.0:
                return True, (
                    f"FRONT-LOADED PACKING: High entropy at start ({avg_first:.2f}) "
                    f"followed by low entropy padding ({avg_last:.2f})"
                )

        # Pattern 4: High standard deviation (>2.0)
        # Indicates inconsistent entropy (suspicious)
        if stddev > 2.0:
            return True, (
                f"HIGH ENTROPY VARIANCE: StdDev={stddev:.2f} indicates mixed content "
                f"(possible packed code with padding)"
            )

        return False, None

    @staticmethod
    def visualize_entropy_distribution(
        entropies: List[float], chunk_size_kb: float
    ) -> str:
        """
        Create ASCII visualization of entropy distribution across section.
        """
        if not entropies:
            return "No data"

        # Create bar chart
        bars = []
        for i, entropy in enumerate(entropies):
            bar_length = int(entropy / 8.0 * 40)  # Scale to 40 chars max
            bar = "█" * bar_length

            # Color code
            if entropy > 7.0:
                marker = "🔴"
            elif entropy < 2.0:
                marker = "🔵"
            else:
                marker = "🟢"

            offset_kb = i * chunk_size_kb
            bars.append(f"  {offset_kb:>6.0f} KB: {marker} {bar:<40} {entropy:.2f}")

        return "\n".join(bars)


"""
Enhanced section analysis combining multiple indicators
"""
from typing import Dict, Tuple
from dataclasses import dataclass


@dataclass
class SectionAnalysis:
    """Comprehensive section analysis result"""

    name: str
    entropy: float
    entropy_status: str
    size_ratio: float
    size_status: str
    permissions: str
    permission_status: str
    suspicion_score: int  # 0-100
    suspicion_level: str  # LOW/MEDIUM/HIGH/CRITICAL
    warnings: list
    is_suspicious: bool


class SectionAnalyzer:
    """Advanced section analysis combining entropy, size, and permissions"""

    # Expected entropy ranges by section type
    EXPECTED_ENTROPY = {
        ".text": (4.5, 6.5),  # Code: moderate entropy
        ".data": (3.0, 6.0),  # Data: variable
        ".rdata": (4.0, 6.5),  # Read-only data: moderate
        ".bss": (0.0, 1.0),  # Uninitialized: very low
        ".rsrc": (5.0, 7.5),  # Resources: can be high (compressed images)
        ".reloc": (2.0, 5.0),  # Relocation table: low-moderate
    }

    # Expected size ratios (VirtualSize / RawSize)
    EXPECTED_SIZE_RATIO = {
        ".text": (0.95, 1.05),  # Code: usually 1:1
        ".data": (0.9, 2.0),  # Data: slight expansion OK
        ".rdata": (0.95, 1.1),  # Read-only: minimal expansion
        ".bss": (1.0, float("inf")),  # BSS: always expands (disk=0)
        ".rsrc": (0.9, 1.2),  # Resources: usually 1:1
        ".reloc": (0.9, 1.5),  # Relocations: slight expansion OK
    }

    @classmethod
    def analyze_section(cls, section: Dict) -> SectionAnalysis:
        """
        Perform comprehensive section analysis.
        Returns SectionAnalysis with suspicion score and detailed breakdown.
        """
        name = section["name"]
        data = section["data"]
        vsize = section["virtual_size"]
        rsize = section["raw_size"]
        perms = section["permissions"]

        # Calculate metrics
        entropy = EntropyAnalyzer.calculate(data)
        size_ratio = vsize / rsize if rsize > 0 else float("inf")

        # Score components
        entropy_score, entropy_status = cls._score_entropy(entropy, name)
        size_score, size_status = cls._score_size_ratio(size_ratio, name, rsize)
        perm_score, perm_status = cls._score_permissions(perms, name)

        # Combine scores
        suspicion_score = cls._calculate_suspicion_score(
            entropy_score, size_score, perm_score, name
        )

        # Generate warnings
        warnings = cls._generate_warnings(
            name, entropy, size_ratio, perms, entropy_score, size_score, perm_score
        )

        # Determine level
        suspicion_level = cls._get_suspicion_level(suspicion_score)
        is_suspicious = suspicion_score >= 50

        return SectionAnalysis(
            name=name,
            entropy=entropy,
            entropy_status=entropy_status,
            size_ratio=size_ratio,
            size_status=size_status,
            permissions=perms,
            permission_status=perm_status,
            suspicion_score=suspicion_score,
            suspicion_level=suspicion_level,
            warnings=warnings,
            is_suspicious=is_suspicious,
        )

    @classmethod
    def _score_entropy(cls, entropy: float, section_name: str) -> Tuple[int, str]:
        """
        Score entropy (0-40 points).
        Returns (score, status_description)
        """
        # Get expected range for this section type
        expected = cls.EXPECTED_ENTROPY.get(section_name, (3.0, 7.0))
        min_expected, max_expected = expected

        # Special case: .bss should have very low entropy
        if section_name == ".bss":
            if entropy < 1.0:
                return 0, "Normal (uninitialized data)"
            else:
                return 30, "⚠️ Suspicious (BSS should be mostly zeros)"

        # High entropy (possible packing/encryption)
        if entropy > 7.5:
            return 40, "⚠️ Very High (Likely packed/encrypted)"
        elif entropy > max_expected:
            return 25, "⚠️ High (Possible obfuscation)"

        # Low entropy (possible padding/sparse code)
        elif entropy < min_expected and section_name == ".text":
            return 15, "⚠️ Low (Sparse code/debugging symbols)"

        # Normal range
        else:
            return 0, "Normal"

    @classmethod
    def _score_size_ratio(
        cls, ratio: float, section_name: str, raw_size: int
    ) -> Tuple[int, str]:
        """
        Score size ratio (0-40 points).
        Returns (score, status_description)
        """
        # Special case: .bss has no disk size (always expands)
        if section_name == ".bss" and raw_size == 0:
            return 0, "Normal (uninitialized data)"

        # Get expected ratio range
        expected = cls.EXPECTED_SIZE_RATIO.get(section_name, (0.9, 2.0))
        min_ratio, max_ratio = expected

        # Extreme expansion (very suspicious for .text)
        if ratio > 10 and section_name == ".text":
            return 40, "🔴 CRITICAL (10x+ expansion - packed code)"
        elif ratio > 5 and section_name == ".text":
            return 35, "🔴 Very High (5x+ expansion - likely packed)"
        elif ratio > 3 and section_name == ".text":
            return 25, "⚠️ High (3x+ expansion - possible packing)"

        # Moderate expansion
        elif ratio > max_ratio:
            if section_name == ".text":
                return 20, "⚠️ Moderate expansion (check for packing)"
            else:
                return 10, "Slight expansion (possibly normal)"

        # Normal ratio
        elif min_ratio <= ratio <= max_ratio:
            return 0, "Normal (1:1 ratio)"

        # Compression (rare, but possible)
        elif ratio < min_ratio:
            return 5, "Compressed on disk (unusual)"

        return 0, "Normal"

    @classmethod
    def _score_permissions(cls, perms: str, section_name: str) -> Tuple[int, str]:
        """
        Score permissions (0-30 points).
        Returns (score, status_description)
        """
        has_r = "R" in perms
        has_w = "W" in perms
        has_x = "X" in perms

        # W+X is very suspicious (self-modifying code)
        if has_w and has_x:
            return 30, "🔴 CRITICAL (W+X - Self-modifying code)"

        # Executable data section (suspicious)
        if has_x and section_name in [".data", ".rdata"]:
            return 20, "⚠️ Suspicious (Executable data section)"

        # Writable code section (unusual but less critical than W+X)
        if has_w and section_name == ".text":
            return 15, "⚠️ Unusual (Writable code section)"

        # Non-executable code section (weird but not dangerous)
        if not has_x and section_name == ".text":
            return 5, "Unusual (Non-executable code)"

        # Normal permissions
        return 0, "Normal"

    @classmethod
    def _calculate_suspicion_score(
        cls, entropy_score: int, size_score: int, perm_score: int, section_name: str
    ) -> int:
        """
        Combine individual scores into overall suspicion score (0-100).
        Uses weighted combination and correlation bonuses.
        """
        base_score = entropy_score + size_score + perm_score

        # Correlation bonus: High entropy + high expansion = likely packing
        if entropy_score >= 25 and size_score >= 25 and section_name == ".text":
            correlation_bonus = 20
        # Medium correlation
        elif entropy_score >= 15 and size_score >= 15:
            correlation_bonus = 10
        else:
            correlation_bonus = 0

        total = min(100, base_score + correlation_bonus)
        return total

    @classmethod
    def _generate_warnings(
        cls,
        name: str,
        entropy: float,
        ratio: float,
        perms: str,
        entropy_score: int,
        size_score: int,
        perm_score: int,
    ) -> list:
        """Generate human-readable warnings"""
        warnings = []

        if entropy_score >= 25:
            warnings.append(
                f"High entropy ({entropy:.2f}) suggests encryption or packing"
            )

        if size_score >= 25 and name == ".text":
            warnings.append(
                f"Section expands {ratio:.1f}x in memory - likely packed code"
            )

        if perm_score >= 20:
            warnings.append(
                f"Dangerous permissions ({perms}) - possible code injection"
            )

        if entropy_score >= 15 and size_score >= 15:
            warnings.append(
                "Combined high entropy + expansion strongly indicates packing"
            )

        return warnings

    @staticmethod
    def _get_suspicion_level(score: int) -> str:
        """Convert numeric score to threat level"""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "CLEAN"

    @classmethod
    def analyze_section(cls, section: Dict) -> SectionAnalysis:
        """Enhanced analysis with segment-level entropy checking"""
        name = section["name"]
        data = section["data"]
        vsize = section["virtual_size"]
        rsize = section["raw_size"]
        perms = section["permissions"]

        # Overall entropy (existing)
        overall_entropy = EntropyAnalyzer.calculate(data)

        # NEW: Segment-level entropy analysis
        segment_analysis = SegmentEntropyAnalyzer.analyze_segments(data)

        # Calculate metrics
        size_ratio = vsize / rsize if rsize > 0 else float("inf")

        # Score components
        entropy_score, entropy_status = cls._score_entropy(overall_entropy, name)
        size_score, size_status = cls._score_size_ratio(size_ratio, name, rsize)
        perm_score, perm_status = cls._score_permissions(perms, name)

        # NEW: Score segment entropy anomalies
        segment_score, segment_status = cls._score_segment_entropy(
            segment_analysis, name
        )

        # Combine scores (now includes segment analysis)
        suspicion_score = cls._calculate_suspicion_score(
            entropy_score, size_score, perm_score, segment_score, name
        )

        # Generate warnings
        warnings = cls._generate_warnings(
            name,
            overall_entropy,
            size_ratio,
            perms,
            entropy_score,
            size_score,
            perm_score,
            segment_score,
            segment_analysis,
        )

        suspicion_level = cls._get_suspicion_level(suspicion_score)
        is_suspicious = suspicion_score >= 50

        return SectionAnalysis(
            name=name,
            entropy=overall_entropy,
            entropy_status=entropy_status,
            size_ratio=size_ratio,
            size_status=size_status,
            permissions=perms,
            permission_status=perm_status,
            suspicion_score=suspicion_score,
            suspicion_level=suspicion_level,
            warnings=warnings,
            is_suspicious=is_suspicious,
            segment_analysis=segment_analysis,  # Add this field
        )

    @classmethod
    def _score_segment_entropy(
        cls, segment_analysis: Dict, section_name: str
    ) -> Tuple[int, str]:
        """
        Score segment entropy anomalies (0-35 points).
        This catches padding-based evasion.
        """
        if not segment_analysis["has_anomaly"]:
            return 0, "Uniform entropy distribution"

        # Anomaly detected - assign score based on severity
        reason = segment_analysis["anomaly_reason"]

        if "PADDING EVASION" in reason:
            return 35, f"🔴 {reason}"
        elif "BIMODAL DISTRIBUTION" in reason:
            return 30, f"🔴 {reason}"
        elif "FRONT-LOADED PACKING" in reason:
            return 30, f"🔴 {reason}"
        elif "HIGH ENTROPY VARIANCE" in reason:
            return 20, f"⚠️ {reason}"

        return 15, f"⚠️ Entropy anomaly detected"

    @classmethod
    def _calculate_suspicion_score(
        cls,
        entropy_score: int,
        size_score: int,
        perm_score: int,
        segment_score: int,
        section_name: str,
    ) -> int:
        """Updated to include segment score"""
        base_score = entropy_score + size_score + perm_score + segment_score

        # Correlation bonus: Overall low entropy BUT segment anomaly = evasion
        if entropy_score < 15 and segment_score >= 25:
            correlation_bonus = 25  # This is the key insight!
        # High entropy + high expansion (existing check)
        elif entropy_score >= 25 and size_score >= 25 and section_name == ".text":
            correlation_bonus = 20
        elif entropy_score >= 15 and size_score >= 15:
            correlation_bonus = 10
        else:
            correlation_bonus = 0

        total = min(100, base_score + correlation_bonus)
        return total

    @classmethod
    def _generate_warnings(
        cls,
        name: str,
        entropy: float,
        ratio: float,
        perms: str,
        entropy_score: int,
        size_score: int,
        perm_score: int,
        segment_score: int,
        segment_analysis: Dict,
    ) -> list:
        """Updated to include segment warnings"""
        warnings = []

        # Existing warnings
        if entropy_score >= 25:
            warnings.append(f"High overall entropy ({entropy:.2f})")

        if size_score >= 25 and name == ".text":
            warnings.append(f"Section expands {ratio:.1f}x in memory")

        if perm_score >= 20:
            warnings.append(f"Dangerous permissions ({perms})")

        # NEW: Segment-level warnings
        if segment_score >= 20:
            warnings.append(segment_analysis["anomaly_reason"])

        # NEW: Evasion detection
        if entropy_score < 15 and segment_score >= 25:
            warnings.append(
                "⚠️ EVASION ATTEMPT: Overall entropy appears normal, but "
                "chunk analysis reveals padding-based obfuscation"
            )

        return warnings
