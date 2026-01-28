"""
Rich Header Analysis Module
Parses the undocumented Microsoft Rich Header to detect:
- Compiler/linker tools used
- Build environment fingerprinting
- Timestamp manipulation (time-stomping)
"""

import struct
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class RichEntry:
    """Single entry in Rich header"""

    tool_id: int
    tool_version: int
    use_count: int
    tool_name: str


@dataclass
class RichHeaderResult:
    """Complete Rich header analysis"""

    present: bool
    valid: bool
    checksum: int
    entries: List[RichEntry]
    raw_data: bytes
    warnings: List[str]
    compiler_info: Dict
    is_suspicious: bool
    suspicion_reasons: List[str]


# Known Microsoft tool IDs (Product IDs)
KNOWN_TOOLS = {
    # Visual Studio 6.0
    (6, 0): "VS6 Linker",
    # Visual Studio 2002 (7.0)
    (7, 0): "VS2002",
    # Visual Studio 2003 (7.1)
    (7, 1): "VS2003",
    # Visual Studio 2005 (8.0)
    (8, 0): "VS2005",
    # Visual Studio 2008 (9.0)
    (9, 0): "VS2008",
    # Visual Studio 2010 (10.0)
    (10, 0): "VS2010",
    # Visual Studio 2012 (11.0)
    (11, 0): "VS2012",
    # Visual Studio 2013 (12.0)
    (12, 0): "VS2013",
    # Visual Studio 2015 (14.0)
    (14, 0): "VS2015",
    # Visual Studio 2017 (14.1x)
    (14, 10): "VS2017",
    (14, 11): "VS2017",
    (14, 12): "VS2017",
    (14, 13): "VS2017",
    (14, 14): "VS2017",
    (14, 15): "VS2017",
    (14, 16): "VS2017",
    # Visual Studio 2019 (14.2x)
    (14, 20): "VS2019",
    (14, 21): "VS2019",
    (14, 22): "VS2019",
    (14, 23): "VS2019",
    (14, 24): "VS2019",
    (14, 25): "VS2019",
    (14, 26): "VS2019",
    (14, 27): "VS2019",
    (14, 28): "VS2019",
    (14, 29): "VS2019",
    # Visual Studio 2022 (14.3x)
    (14, 30): "VS2022",
    (14, 31): "VS2022",
    (14, 32): "VS2022",
    (14, 33): "VS2022",
    (14, 34): "VS2022",
    (14, 35): "VS2022",
    (14, 36): "VS2022",
    (14, 37): "VS2022",
    (14, 38): "VS2022",
    (14, 39): "VS2022",
    (14, 40): "VS2022",
}

# Tool type IDs
TOOL_TYPES = {
    0x00: "Unknown",
    0x01: "Import",
    0x02: "Export",
    0x04: "Resource",
    0x06: "Pre-VC++ 6.0",
    0x0A: "MASM",
    0x0F: "Linker",
    0x15: "C Compiler",
    0x16: "C Compiler",
    0x19: "C++ Compiler",
    0x1C: "C++ Compiler",
    0x5D: "MASM",
    0x5E: "MASM",
    0x5F: "MASM",
    0x60: "MASM",
    0x7B: "MASM",
    0x7C: "C Compiler",
    0x7D: "C++ Compiler",
    0x83: "Linker",
    0x84: "Export",
    0x85: "Import",
    0x86: "Resource",
    0x91: "MASM",
    0x92: "C Compiler",
    0x93: "C++ Compiler",
    0x94: "Linker",
    0x95: "Export",
    0x96: "Import",
    0xFF: "Linker",
}


class RichHeaderAnalyzer:
    """Analyze PE Rich Header for build environment fingerprinting"""

    DANS_SIGNATURE = b"DanS"
    RICH_SIGNATURE = b"Rich"

    def __init__(self, pe_data: bytes):
        self.data = pe_data

    def analyze(self) -> RichHeaderResult:
        """
        Parse and analyze Rich header.

        The Rich header is XOR-encrypted with a checksum key.
        Structure: DanS ^ key | padding ^ key | entries ^ key | Rich | key
        """
        warnings = []
        suspicion_reasons = []

        # Find Rich signature
        rich_offset = self.data.find(self.RICH_SIGNATURE)

        if rich_offset == -1:
            return RichHeaderResult(
                present=False,
                valid=False,
                checksum=0,
                entries=[],
                raw_data=b"",
                warnings=["No Rich header found (non-MSVC compiler or stripped)"],
                compiler_info={},
                is_suspicious=False,
                suspicion_reasons=[],
            )

        # Get XOR key (4 bytes after "Rich")
        if rich_offset + 8 > len(self.data):
            return RichHeaderResult(
                present=True,
                valid=False,
                checksum=0,
                entries=[],
                raw_data=b"",
                warnings=["Rich header truncated"],
                compiler_info={},
                is_suspicious=True,
                suspicion_reasons=["Malformed Rich header"],
            )

        xor_key = struct.unpack("<I", self.data[rich_offset + 4 : rich_offset + 8])[0]

        # Search backwards for DanS signature
        dans_offset = None
        for i in range(rich_offset - 4, 0x40, -4):  # Start after DOS header
            decrypted = struct.unpack("<I", self.data[i : i + 4])[0] ^ xor_key
            if decrypted == struct.unpack("<I", self.DANS_SIGNATURE)[0]:
                dans_offset = i
                break

        if dans_offset is None:
            return RichHeaderResult(
                present=True,
                valid=False,
                checksum=xor_key,
                entries=[],
                raw_data=(
                    self.data[0x80 : rich_offset + 8] if rich_offset > 0x80 else b""
                ),
                warnings=["Could not locate DanS signature"],
                compiler_info={},
                is_suspicious=True,
                suspicion_reasons=["Rich header corrupted or manipulated"],
            )

        # Extract and decrypt Rich header
        raw_data = self.data[dans_offset : rich_offset + 8]

        # Decrypt entries (skip DanS + 3 padding DWORDs = 16 bytes)
        entries = []
        entry_start = dans_offset + 16

        for i in range(entry_start, rich_offset, 8):
            if i + 8 > len(self.data):
                break

            val1 = struct.unpack("<I", self.data[i : i + 4])[0] ^ xor_key
            val2 = struct.unpack("<I", self.data[i + 4 : i + 8])[0] ^ xor_key

            # val1 = (build_id << 16) | product_id
            # val2 = use_count
            product_id = val1 & 0xFFFF
            build_id = (val1 >> 16) & 0xFFFF
            use_count = val2

            if use_count == 0:
                continue

            # Determine tool name
            tool_type = TOOL_TYPES.get(product_id, f"Unknown (0x{product_id:02X})")

            entries.append(
                RichEntry(
                    tool_id=product_id,
                    tool_version=build_id,
                    use_count=use_count,
                    tool_name=tool_type,
                )
            )

        # Analyze compiler info
        compiler_info = self._analyze_compiler(entries)

        # Verify checksum
        calculated_checksum = self._calculate_checksum(dans_offset)
        if calculated_checksum != xor_key:
            warnings.append(
                f"Checksum mismatch: expected {xor_key:08X}, got {calculated_checksum:08X}"
            )
            suspicion_reasons.append("Rich header checksum invalid (possibly tampered)")

        # Check for suspicious patterns
        is_suspicious, reasons = self._check_suspicious(entries, compiler_info)
        suspicion_reasons.extend(reasons)

        return RichHeaderResult(
            present=True,
            valid=calculated_checksum == xor_key,
            checksum=xor_key,
            entries=entries,
            raw_data=raw_data,
            warnings=warnings,
            compiler_info=compiler_info,
            is_suspicious=is_suspicious or len(suspicion_reasons) > 0,
            suspicion_reasons=suspicion_reasons,
        )

    def _calculate_checksum(self, dans_offset: int) -> int:
        """Calculate Rich header checksum"""
        checksum = dans_offset

        # Add DOS header contribution
        for i in range(0, 0x3C):  # Up to e_lfanew
            checksum += self.data[i] << (i % 32)
            checksum &= 0xFFFFFFFF

        return checksum

    def _analyze_compiler(self, entries: List[RichEntry]) -> Dict:
        """Determine likely compiler/Visual Studio version"""
        if not entries:
            return {"detected": False}

        # Find highest build version
        max_build = max(e.tool_version for e in entries)

        # Estimate VS version from build number
        vs_version = "Unknown"
        vs_year = 0

        if max_build >= 30000:
            vs_version = "VS2022"
            vs_year = 2022
        elif max_build >= 29000:
            vs_version = "VS2019"
            vs_year = 2019
        elif max_build >= 26000:
            vs_version = "VS2017"
            vs_year = 2017
        elif max_build >= 24000:
            vs_version = "VS2015"
            vs_year = 2015
        elif max_build >= 21000:
            vs_version = "VS2013"
            vs_year = 2013
        elif max_build >= 17000:
            vs_version = "VS2012"
            vs_year = 2012
        elif max_build >= 15000:
            vs_version = "VS2010"
            vs_year = 2010
        elif max_build >= 11000:
            vs_version = "VS2008"
            vs_year = 2008
        elif max_build >= 8000:
            vs_version = "VS2005"
            vs_year = 2005

        # Count tool types
        compilers = [e for e in entries if "Compiler" in e.tool_name]
        linkers = [e for e in entries if "Linker" in e.tool_name]

        return {
            "detected": True,
            "visual_studio": vs_version,
            "vs_year": vs_year,
            "max_build": max_build,
            "total_entries": len(entries),
            "compiler_count": len(compilers),
            "linker_count": len(linkers),
            "has_masm": any("MASM" in e.tool_name for e in entries),
        }

    def _check_suspicious(self, entries: List[RichEntry], compiler_info: Dict) -> tuple:
        """Check for suspicious patterns in Rich header"""
        suspicious = False
        reasons = []

        if not entries:
            return False, []

        # Very few entries is suspicious (stripped/modified)
        if len(entries) < 3:
            suspicious = True
            reasons.append(
                f"Unusually few Rich entries ({len(entries)}) - possible manipulation"
            )

        # Check for mixed Visual Studio versions (unusual)
        builds = [e.tool_version for e in entries]
        build_range = max(builds) - min(builds)
        if build_range > 10000:
            suspicious = True
            reasons.append(
                f"Wide build number range ({build_range}) - mixed toolchain versions"
            )

        # Ancient compiler version is suspicious for recent timestamp
        if compiler_info.get("vs_year", 2020) < 2010:
            suspicious = True
            reasons.append(
                f"Ancient compiler detected ({compiler_info.get('visual_studio')}) - unusual for modern malware"
            )

        return suspicious, reasons


def analyze_rich_header(filepath: str) -> RichHeaderResult:
    """Convenience function to analyze Rich header from file"""
    with open(filepath, "rb") as f:
        data = f.read(4096)  # Rich header is in first 4KB

    analyzer = RichHeaderAnalyzer(data)
    return analyzer.analyze()


def check_timestamp_anomaly(rich_result: RichHeaderResult, pe_timestamp: int) -> Dict:
    """
    Check for timestamp manipulation by comparing Rich header compiler
    version against PE timestamp.

    Args:
        rich_result: Result from RichHeaderAnalyzer
        pe_timestamp: TimeDateStamp from PE header

    Returns:
        Dict with anomaly detection results
    """
    if not rich_result.present or not rich_result.compiler_info.get("detected"):
        return {"checked": False, "reason": "No Rich header data"}

    vs_year = rich_result.compiler_info.get("vs_year", 0)

    if vs_year == 0:
        return {"checked": False, "reason": "Could not determine VS version"}

    # Convert PE timestamp to year
    try:
        pe_date = datetime.fromtimestamp(pe_timestamp)
        pe_year = pe_date.year
    except:
        return {"checked": False, "reason": "Invalid PE timestamp"}

    anomalies = []
    is_anomalous = False

    # Check if PE timestamp predates compiler
    if pe_year < vs_year:
        is_anomalous = True
        anomalies.append(f"PE timestamp ({pe_year}) predates compiler ({vs_year})")

    # Check if PE timestamp is unrealistically old
    if pe_year < 2000:
        is_anomalous = True
        anomalies.append(f"PE timestamp is before year 2000 ({pe_year})")

    # Check if PE timestamp is in the future
    current_year = datetime.now().year
    if pe_year > current_year:
        is_anomalous = True
        anomalies.append(f"PE timestamp is in the future ({pe_year})")

    # Check for large gap between compiler and timestamp
    year_gap = pe_year - vs_year
    if year_gap > 10:
        anomalies.append(f"Large gap ({year_gap} years) between compiler and timestamp")

    return {
        "checked": True,
        "is_anomalous": is_anomalous,
        "pe_year": pe_year,
        "compiler_year": vs_year,
        "anomalies": anomalies,
        "verdict": "TIME-STOMPED" if is_anomalous else "CONSISTENT",
    }
