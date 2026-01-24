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
