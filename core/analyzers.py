"""
Various analysis functions: entropy, packer detection, section analysis
Now integrated with configuration layer.
"""

import math
import statistics
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass

from .config import AnalysisConfig, DEFAULT_CONFIG


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
    suspicion_score: int
    suspicion_level: str
    warnings: List[str]
    is_suspicious: bool
    segment_analysis: Dict


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


class SegmentEntropyAnalyzer:
    """
    Detect entropy anomalies within sections by analyzing chunks.
    Catches padding-based evasion techniques.
    """

    def __init__(self, config: AnalysisConfig = None):
        self.config = config or DEFAULT_CONFIG

    def analyze_segments(self, data: bytes, chunk_size: int = None) -> Dict:
        """
        Break section into chunks and analyze entropy distribution.

        Args:
            data: Section data bytes
            chunk_size: Size of each chunk (default from config)

        Returns:
            Dictionary with entropy statistics and anomaly flags
        """
        if chunk_size is None:
            chunk_size = self.config.entropy.chunk_size

        if len(data) < chunk_size:
            overall_entropy = EntropyAnalyzer.calculate(data)
            return {
                "chunk_count": 1,
                "entropies": [overall_entropy],
                "mean": overall_entropy,
                "stddev": 0.0,
                "max": overall_entropy,
                "min": overall_entropy,
                "variance": 0.0,
                "has_anomaly": False,
                "anomaly_reason": None,
                "chunk_size_kb": chunk_size / 1024,
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
                "chunk_size_kb": chunk_size / 1024,
            }

        # Statistical analysis
        mean_entropy = statistics.mean(entropies)
        stddev_entropy = statistics.stdev(entropies)
        max_entropy = max(entropies)
        min_entropy = min(entropies)
        variance = max_entropy - min_entropy

        # Detect anomalies
        has_anomaly, reason = self._detect_anomaly(
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

    def _detect_anomaly(
        self, entropies: List[float], mean: float, stddev: float, variance: float
    ) -> Tuple[bool, Optional[str]]:
        """Detect if entropy distribution indicates padding/packing evasion"""
        cfg = self.config.entropy

        # Pattern 1: High variance
        if variance > cfg.variance_threshold:
            high_chunks = [e for e in entropies if e > cfg.high]
            low_chunks = [e for e in entropies if e < 2.0]

            if high_chunks and low_chunks:
                return True, (
                    f"PADDING EVASION: {len(high_chunks)} high-entropy chunks "
                    f"+ {len(low_chunks)} low-entropy chunks"
                )

        # Pattern 2: Bimodal distribution
        high_entropy_count = sum(1 for e in entropies if e > 6.5)
        low_entropy_count = sum(1 for e in entropies if e < 2.0)
        total = len(entropies)

        if high_entropy_count > 0 and low_entropy_count > 0:
            if (high_entropy_count + low_entropy_count) / total > 0.7:
                return True, (
                    f"BIMODAL DISTRIBUTION: {high_entropy_count} packed + "
                    f"{low_entropy_count} padding chunks"
                )

        # Pattern 3: Front-loaded packing
        if len(entropies) >= 3:
            first_third = entropies[: len(entropies) // 3]
            last_third = entropies[-len(entropies) // 3 :]

            avg_first = statistics.mean(first_third)
            avg_last = statistics.mean(last_third)

            if avg_first > cfg.high and avg_last < 2.0:
                return True, (
                    f"FRONT-LOADED PACKING: High start ({avg_first:.2f}) "
                    f"+ low end ({avg_last:.2f})"
                )

        # Pattern 4: High standard deviation
        if stddev > 2.0:
            return True, (f"HIGH VARIANCE: StdDev={stddev:.2f} (mixed content)")

        return False, None

    def visualize_entropy_distribution(
        self, entropies: List[float], chunk_size_kb: float, section_name: str = None
    ) -> str:
        """Create context-aware ASCII visualization"""
        if not entropies:
            return "No data"

        cfg = self.config.entropy

        # Get expected range
        if section_name:
            expected = cfg.section_ranges.get(section_name, (3.0, 7.0))
            min_expected, max_expected = expected
        else:
            min_expected, max_expected = 3.0, 7.0

        bars = []
        for i, entropy in enumerate(entropies):
            bar_length = int(entropy / 8.0 * 40)
            bar = "█" * bar_length

            # Context-aware markers
            if entropy > max_expected + 0.5:
                ctx_marker = "⚠️"
            elif entropy < min_expected:
                ctx_marker = "❄️"
            else:
                ctx_marker = "✓"

            # Absolute threshold markers
            if entropy > cfg.critical:
                abs_marker = "🔴"
            elif entropy > cfg.high:
                abs_marker = "🟠"
            elif entropy < cfg.empty:
                abs_marker = "🔵"
            else:
                abs_marker = ""

            offset_kb = i * chunk_size_kb
            marker = f"{ctx_marker}{abs_marker}".ljust(3)

            bars.append(f"  {offset_kb:>6.0f} KB: {marker} {bar:<40} {entropy:.2f}")

        legend = (
            f"\n  Expected range for {section_name or 'section'}: "
            f"{min_expected:.1f} - {max_expected:.1f}\n"
            f"  ✓ = Within range | ⚠️ = Above range | ❄️ = Below range\n"
            f"  🔴 = Critical (>{cfg.critical}) | 🟠 = High (>{cfg.high}) | 🔵 = Empty (<{cfg.empty})"
        )

        return "\n".join(bars) + legend


class SectionAnalyzer:
    """Advanced section analysis combining entropy, size, and permissions"""

    def __init__(self, config: AnalysisConfig = None):
        self.config = config or DEFAULT_CONFIG
        self.segment_analyzer = SegmentEntropyAnalyzer(config)

    def analyze_section(self, section: Dict) -> SectionAnalysis:
        """Perform comprehensive section analysis"""
        name = section["name"]
        data = section["data"]
        vsize = section["virtual_size"]
        rsize = section["raw_size"]
        perms = section["permissions"]

        # Overall entropy
        overall_entropy = EntropyAnalyzer.calculate(data)

        # Segment-level entropy analysis
        segment_analysis = self.segment_analyzer.analyze_segments(data)

        # Calculate metrics
        size_ratio = vsize / rsize if rsize > 0 else float("inf")

        # Score components
        entropy_score, entropy_status = self._score_entropy(overall_entropy, name)
        size_score, size_status = self._score_size_ratio(size_ratio, name, rsize)
        perm_score, perm_status = self._score_permissions(perms, name)
        segment_score, segment_status = self._score_segment_entropy(
            segment_analysis, name
        )

        # Combine scores
        suspicion_score = self._calculate_suspicion_score(
            entropy_score, size_score, perm_score, segment_score, name
        )

        # Generate warnings
        warnings = self._generate_warnings(
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

        suspicion_level = self._get_suspicion_level(suspicion_score)
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
            segment_analysis=segment_analysis,
        )

    def _score_entropy(self, entropy: float, section_name: str) -> Tuple[int, str]:
        """Score entropy (0-40 points)"""
        cfg = self.config.entropy
        expected = cfg.section_ranges.get(section_name, (3.0, 7.0))
        min_expected, max_expected = expected

        if section_name == ".bss":
            if entropy < cfg.empty:
                return 0, "Normal (uninitialized data)"
            else:
                return 30, "⚠️ Suspicious (BSS should be zeros)"

        if entropy > cfg.critical:
            return 40, "⚠️ Very High (Likely packed/encrypted)"
        elif entropy > max_expected:
            return 25, "⚠️ High (Possible obfuscation)"
        elif entropy < min_expected and section_name == ".text":
            return 15, "⚠️ Low (Sparse code)"
        else:
            return 0, "Normal"

    def _score_size_ratio(
        self, ratio: float, section_name: str, raw_size: int
    ) -> Tuple[int, str]:
        """Score size ratio (0-40 points)"""
        cfg = self.config.size

        if section_name == ".bss" and raw_size == 0:
            return 0, "Normal (uninitialized data)"

        expected = cfg.section_ratios.get(section_name, (0.9, 2.0))
        min_ratio, max_ratio = expected

        if ratio > cfg.expansion_ratio_critical and section_name == ".text":
            return 40, "🔴 CRITICAL (10x+ expansion)"
        elif ratio > cfg.expansion_ratio_very_high and section_name == ".text":
            return 35, "🔴 Very High (5x+ expansion)"
        elif ratio > cfg.expansion_ratio_high and section_name == ".text":
            return 25, "⚠️ High (3x+ expansion)"
        elif ratio > max_ratio:
            if section_name == ".text":
                return 20, "⚠️ Moderate expansion"
            else:
                return 10, "Slight expansion"
        elif min_ratio <= ratio <= max_ratio:
            return 0, "Normal (1:1 ratio)"
        else:
            return 5, "Compressed (unusual)"

    def _score_permissions(self, perms: str, section_name: str) -> Tuple[int, str]:
        """Score permissions (0-30 points)"""
        has_w = "W" in perms
        has_x = "X" in perms

        if has_w and has_x:
            return 30, "🔴 CRITICAL (W+X)"
        elif has_x and section_name in [".data", ".rdata"]:
            return 20, "⚠️ Suspicious (Executable data)"
        elif has_w and section_name == ".text":
            return 15, "⚠️ Unusual (Writable code)"
        elif not has_x and section_name == ".text":
            return 5, "Unusual (Non-executable code)"
        else:
            return 0, "Normal"

    def _score_segment_entropy(
        self, segment_analysis: Dict, section_name: str
    ) -> Tuple[int, str]:
        """Score segment entropy anomalies (0-35 points)"""
        if not segment_analysis["has_anomaly"]:
            return 0, "Uniform entropy"

        reason = segment_analysis["anomaly_reason"]

        if "PADDING EVASION" in reason:
            return 35, f"🔴 {reason}"
        elif "BIMODAL" in reason:
            return 30, f"🔴 {reason}"
        elif "FRONT-LOADED" in reason:
            return 30, f"🔴 {reason}"
        elif "HIGH VARIANCE" in reason:
            return 20, f"⚠️ {reason}"

        return 15, "⚠️ Entropy anomaly"

    def _calculate_suspicion_score(
        self,
        entropy_score: int,
        size_score: int,
        perm_score: int,
        segment_score: int,
        section_name: str,
    ) -> int:
        """Combine scores with correlation bonuses"""
        cfg = self.config.scoring
        base_score = entropy_score + size_score + perm_score + segment_score

        # KEY: Low overall entropy BUT segment anomaly = evasion
        if entropy_score < 15 and segment_score >= 25:
            correlation_bonus = cfg.entropy_segment_correlation_bonus
        elif entropy_score >= 25 and size_score >= 25 and section_name == ".text":
            correlation_bonus = cfg.entropy_size_high_correlation_bonus
        elif entropy_score >= 15 and size_score >= 15:
            correlation_bonus = cfg.entropy_size_moderate_correlation_bonus
        else:
            correlation_bonus = 0

        return min(cfg.max_structural_score, base_score + correlation_bonus)

    def _generate_warnings(
        self,
        name: str,
        entropy: float,
        ratio: float,
        perms: str,
        entropy_score: int,
        size_score: int,
        perm_score: int,
        segment_score: int,
        segment_analysis: Dict,
    ) -> List[str]:
        """Generate warnings"""
        warnings = []

        if entropy_score >= 25:
            warnings.append(f"High overall entropy ({entropy:.2f})")

        if size_score >= 25 and name == ".text":
            warnings.append(f"Section expands {ratio:.1f}x in memory")

        if perm_score >= 20:
            warnings.append(f"Dangerous permissions ({perms})")

        if segment_score >= 20:
            warnings.append(segment_analysis["anomaly_reason"])

        # EVASION DETECTION
        if entropy_score < 15 and segment_score >= 25:
            warnings.append(
                "⚠️ EVASION: Overall entropy normal, but chunk analysis reveals padding"
            )

        return warnings

    def _get_suspicion_level(self, score: int) -> str:
        """Convert score to level"""
        cfg = self.config.scoring

        if score >= cfg.critical_threshold:
            return "CRITICAL"
        elif score >= cfg.high_threshold:
            return "HIGH"
        elif score >= cfg.medium_threshold:
            return "MEDIUM"
        elif score >= cfg.low_threshold:
            return "LOW"
        else:
            return "CLEAN"


class PackerDetector:
    """Detect common packers and obfuscation"""

    KNOWN_PACKERS = {
        "UPX": ["UPX0", "UPX1", "UPX2"],
        "ASPack": [".aspack", ".adata"],
        "PECompact": ["PEC2", "PECompact2"],
        "Themida": [".themida"],
        "VMProtect": [".vmp0", ".vmp1", ".vmp2"],
        "Enigma": [".enigma1", ".enigma2"],
        "MPRESS": [".MPRESS1", ".MPRESS2"],
        "NSPack": [".nsp0", ".nsp1", ".nsp2"],
        "PESpin": [".pespin"],
        "Petite": [".petite"],
        "FSG": [".FSG"],
        "MEW": ["MEW"],
        "Armadillo": [".text1", ".text2", ".text3"],  # Multiple .text sections
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
                    if packer not in detected:
                        detected.append(packer)
                    break

        # Additional heuristics
        section_names = [s["name"] for s in sections]

        # Multiple .text sections can indicate Armadillo or custom packer
        text_count = sum(1 for n in section_names if n.startswith(".text"))
        if text_count > 1 and "Armadillo" not in detected:
            detected.append("CustomPacker (multiple .text)")

        # Non-standard section names
        standard_names = {
            ".text",
            ".data",
            ".rdata",
            ".bss",
            ".rsrc",
            ".reloc",
            ".idata",
            ".edata",
        }
        non_standard = [
            n
            for n in section_names
            if n not in standard_names and not n.startswith(".")
        ]
        if len(non_standard) > 2:
            detected.append("CustomPacker (non-standard sections)")

        return detected

    @classmethod
    def analyze_packing_indicators(
        cls, sections: List[Dict], config: AnalysisConfig = None
    ) -> Dict:
        """Comprehensive packing analysis"""
        config = config or DEFAULT_CONFIG

        detected_packers = cls.detect_known_packers(sections)
        indicators = []
        packing_score = 0

        for section in sections:
            entropy = EntropyAnalyzer.calculate(section["data"])

            # High entropy in executable section
            if entropy > config.entropy.critical and "X" in section.get(
                "permissions", ""
            ):
                indicators.append(
                    f"High entropy in executable {section['name']}: {entropy:.2f}"
                )
                packing_score += 25

            # Small raw size but large virtual size
            if section["raw_size"] > 0:
                ratio = section["virtual_size"] / section["raw_size"]
                if ratio > config.size.expansion_ratio_very_high:
                    indicators.append(
                        f"Section {section['name']} expands {ratio:.1f}x in memory"
                    )
                    packing_score += 20

        if detected_packers:
            packing_score += 30

        return {
            "is_packed": packing_score >= 40,
            "packing_score": min(100, packing_score),
            "detected_packers": detected_packers,
            "indicators": indicators,
        }
