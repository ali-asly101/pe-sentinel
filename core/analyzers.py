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
