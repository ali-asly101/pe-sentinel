"""
String Analysis Module
Extracts and analyzes strings for suspicious patterns.
Catches indicators that API analysis alone would miss.
"""

import re
import base64
from typing import List, Dict, Tuple, Set
from dataclasses import dataclass
from collections import defaultdict

from .config import AnalysisConfig, DEFAULT_CONFIG


@dataclass
class StringMatch:
    """Represents a suspicious string match"""

    string: str
    pattern_type: str
    score: int
    context: str  # Why this is suspicious


@dataclass
class StringAnalysisResult:
    """Complete string analysis result"""

    total_strings: int
    ascii_count: int
    unicode_count: int

    suspicious_strings: List[StringMatch]
    suspicious_score: int

    urls: List[str]
    ip_addresses: List[str]
    file_paths: List[str]
    registry_keys: List[str]

    interesting_strings: List[str]  # Non-suspicious but noteworthy

    warnings: List[str]


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

    @staticmethod
    def extract_all(data: bytes, min_length: int = 4) -> Tuple[List[str], List[str]]:
        """Extract both ASCII and Unicode strings"""
        ascii_strings = StringExtractor.extract_ascii(data, min_length)
        unicode_strings = StringExtractor.extract_unicode(data, min_length)
        return ascii_strings, unicode_strings


class SuspiciousPatterns:
    """Definitions of suspicious string patterns"""

    # Network indicators
    URL_PATTERN = re.compile(
        r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+", re.IGNORECASE
    )

    IP_PATTERN = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )

    # Persistence patterns
    REGISTRY_RUN = re.compile(
        r"SOFTWARE\\\\?(Microsoft\\\\?Windows\\\\?CurrentVersion\\\\?Run|"
        r"Wow6432Node\\\\?Microsoft\\\\?Windows\\\\?CurrentVersion\\\\?Run)",
        re.IGNORECASE,
    )

    REGISTRY_SERVICES = re.compile(
        r"SYSTEM\\\\?CurrentControlSet\\\\?Services", re.IGNORECASE
    )

    STARTUP_FOLDER = re.compile(
        r"(AppData\\\\?Roaming\\\\?Microsoft\\\\?Windows\\\\?Start Menu\\\\?Programs\\\\?Startup|"
        r"ProgramData\\\\?Microsoft\\\\?Windows\\\\?Start Menu\\\\?Programs\\\\?Startup)",
        re.IGNORECASE,
    )

    # Command execution
    POWERSHELL_ENCODED = re.compile(
        r"powershell.*-e(nc(odedcommand)?)?[\s]+[A-Za-z0-9+/=]{20,}", re.IGNORECASE
    )

    POWERSHELL_EXEC = re.compile(
        r"(powershell|pwsh).*(-c|-command|iex|invoke-expression|"
        r"downloadstring|downloadfile|webclient|bitstransfer)",
        re.IGNORECASE,
    )

    CMD_EXEC = re.compile(r"cmd(\.exe)?\s*/c\s+", re.IGNORECASE)

    WMIC_EXEC = re.compile(
        r"wmic\s+(process|os|computersystem|shadowcopy)", re.IGNORECASE
    )

    # Ransomware indicators
    SHADOW_DELETE = re.compile(
        r"(vssadmin.*delete|vssadmin.*shadows|"
        r"wmic.*shadowcopy.*delete|"
        r"bcdedit.*recoveryenabled.*no|"
        r"wbadmin.*delete.*catalog)",
        re.IGNORECASE,
    )

    RANSOMWARE_EXTENSIONS = re.compile(
        r"\.(locked|encrypted|crypted|crypt|enc|cry|corona|"
        r"wanna|wcry|locky|cerber|sage|dharma|phobos|"
        r"ryuk|maze|revil|sodinokibi|conti)\b",
        re.IGNORECASE,
    )

    RANSOMWARE_NOTES = re.compile(
        r"(your files (have been|are) encrypted|"
        r"decrypt(ion)? (key|tool|software)|"
        r"bitcoin wallet|btc address|"
        r"pay.*ransom|ransom.*pay|"
        r"recover your files|"
        r"readme.*decrypt|decrypt.*readme)",
        re.IGNORECASE,
    )

    # Credential theft
    PASSWORD_HARVEST = re.compile(
        r"(credentialmanager|vaultcli|"
        r"chrome.*login.*data|firefox.*logins\.json|"
        r"passwords?\.txt|credentials?\.txt|"
        r"mimikatz|sekurlsa|lsass)",
        re.IGNORECASE,
    )

    CRYPTO_WALLET = re.compile(
        r"(wallet\.dat|bitcoin|ethereum|monero|"
        r"electrum|exodus|jaxx|"
        r"blockchain.*wallet)",
        re.IGNORECASE,
    )

    # Keylogger indicators
    KEYLOGGER = re.compile(
        r"(keylog|keystroke|getasynckeystate|"
        r"setwindowshook|keyboard.*hook|"
        r"clipboard.*monitor)",
        re.IGNORECASE,
    )

    # Security evasion
    DISABLE_DEFENDER = re.compile(
        r"(set-mppreference.*-disablerealtimemonitoring|"
        r"windows defender.*disable|"
        r"disable.*antivirus|"
        r"taskkill.*/f.*/im.*(msmpeng|msseces|avast|avg|norton|mcafee|kaspersky))",
        re.IGNORECASE,
    )

    AMSI_BYPASS = re.compile(
        r"(amsiutils|amsiinitfailed|amsi.*bypass|" r"amsi.*patch|amsi\.dll)",
        re.IGNORECASE,
    )

    # Base64 blobs (potential encoded payloads)
    BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{50,}={0,2}")

    # File system paths
    WINDOWS_PATH = re.compile(
        r'[A-Za-z]:\\\\?(?:[^\\/:*?"<>|\r\n]+\\\\?)*[^\\/:*?"<>|\r\n]*', re.IGNORECASE
    )

    TEMP_PATH = re.compile(
        r"(%temp%|%tmp%|\\\\?temp\\\\?|\\\\?tmp\\\\?|" r"appdata\\\\?local\\\\?temp)",
        re.IGNORECASE,
    )


class StringAnalyzer:
    """Analyze extracted strings for suspicious patterns"""

    def __init__(self, config: AnalysisConfig = None):
        self.config = config or DEFAULT_CONFIG
        self.patterns = SuspiciousPatterns()

    def analyze(self, data: bytes) -> StringAnalysisResult:
        """
        Perform complete string analysis on binary data.

        Args:
            data: Raw binary data

        Returns:
            StringAnalysisResult with all findings
        """
        min_len = self.config.strings.min_string_length
        max_strings = self.config.strings.max_strings_to_analyze

        # Extract strings
        ascii_strings, unicode_strings = StringExtractor.extract_all(data, min_len)

        # Deduplicate and limit
        all_strings = list(set(ascii_strings + unicode_strings))[:max_strings]

        # Initialize results
        suspicious_strings = []
        urls = []
        ip_addresses = []
        file_paths = []
        registry_keys = []
        interesting_strings = []
        warnings = []

        total_score = 0

        for s in all_strings:
            matches = self._check_patterns(s)

            for match in matches:
                suspicious_strings.append(match)
                total_score += match.score

            # Categorize even non-suspicious findings
            if self.patterns.URL_PATTERN.search(s):
                urls.append(s)

            if self.patterns.IP_PATTERN.search(s):
                ip_addresses.append(s)

            if self.patterns.WINDOWS_PATH.search(s):
                file_paths.append(s)

            if "SOFTWARE\\" in s.upper() or "SYSTEM\\" in s.upper():
                registry_keys.append(s)

            # Check for interesting but not necessarily malicious strings
            if self._is_interesting(s):
                interesting_strings.append(s)

        # Generate warnings based on findings
        warnings = self._generate_warnings(
            suspicious_strings, urls, ip_addresses, registry_keys
        )

        return StringAnalysisResult(
            total_strings=len(all_strings),
            ascii_count=len(ascii_strings),
            unicode_count=len(unicode_strings),
            suspicious_strings=suspicious_strings,
            suspicious_score=total_score,
            urls=urls[:50],  # Limit for sanity
            ip_addresses=list(set(ip_addresses))[:20],
            file_paths=file_paths[:50],
            registry_keys=list(set(registry_keys))[:30],
            interesting_strings=interesting_strings[:50],
            warnings=warnings,
        )

    def _check_patterns(self, s: str) -> List[StringMatch]:
        """Check a string against all suspicious patterns"""
        matches = []
        scores = self.config.strings.pattern_scores

        # Ransomware indicators (highest priority)
        if self.patterns.SHADOW_DELETE.search(s):
            matches.append(
                StringMatch(
                    string=s[:100],
                    pattern_type="shadow_delete",
                    score=scores.get("shadow_delete", 30),
                    context="Shadow copy deletion - ransomware indicator",
                )
            )

        if self.patterns.RANSOMWARE_NOTES.search(s):
            matches.append(
                StringMatch(
                    string=s[:100],
                    pattern_type="ransomware_note",
                    score=scores.get("ransomware_note", 35),
                    context="Ransomware note language detected",
                )
            )

        if self.patterns.RANSOMWARE_EXTENSIONS.search(s):
            matches.append(
                StringMatch(
                    string=s[:100],
                    pattern_type="ransomware_extension",
                    score=scores.get("ransomware_note", 35),
                    context="Known ransomware file extension",
                )
            )

        # Security evasion
        if self.patterns.DISABLE_DEFENDER.search(s):
            matches.append(
                StringMatch(
                    string=s[:100],
                    pattern_type="disable_defender",
                    score=scores.get("disable_defender", 25),
                    context="Attempts to disable security software",
                )
            )

        if self.patterns.AMSI_BYPASS.search(s):
            matches.append(
                StringMatch(
                    string=s[:100],
                    pattern_type="amsi_bypass",
                    score=scores.get("disable_defender", 25),
                    context="AMSI bypass technique",
                )
            )

        # Command execution
        if self.patterns.POWERSHELL_ENCODED.search(s):
            matches.append(
                StringMatch(
                    string=s[:100],
                    pattern_type="powershell_encoded",
                    score=scores.get("powershell_encoded", 25),
                    context="Encoded PowerShell command",
                )
            )

        if self.patterns.POWERSHELL_EXEC.search(s):
            matches.append(
                StringMatch(
                    string=s[:100],
                    pattern_type="powershell_exec",
                    score=scores.get("powershell_exec", 15),
                    context="PowerShell execution pattern",
                )
            )

        if self.patterns.CMD_EXEC.search(s):
            matches.append(
                StringMatch(
                    string=s[:100],
                    pattern_type="cmd_exec",
                    score=scores.get("cmd_exec", 10),
                    context="Command shell execution",
                )
            )

        if self.patterns.WMIC_EXEC.search(s):
            matches.append(
                StringMatch(
                    string=s[:100],
                    pattern_type="wmic_exec",
                    score=scores.get("cmd_exec", 10),
                    context="WMIC execution pattern",
                )
            )

        # Credential theft
        if self.patterns.PASSWORD_HARVEST.search(s):
            matches.append(
                StringMatch(
                    string=s[:100],
                    pattern_type="password_harvest",
                    score=scores.get("password_harvest", 15),
                    context="Credential harvesting indicator",
                )
            )

        if self.patterns.CRYPTO_WALLET.search(s):
            matches.append(
                StringMatch(
                    string=s[:100],
                    pattern_type="crypto_wallet",
                    score=scores.get("crypto_wallet", 20),
                    context="Cryptocurrency wallet targeting",
                )
            )

        # Keylogger
        if self.patterns.KEYLOGGER.search(s):
            matches.append(
                StringMatch(
                    string=s[:100],
                    pattern_type="keylogger_indicator",
                    score=scores.get("keylogger_indicator", 20),
                    context="Keylogger/input capture indicator",
                )
            )

        # Persistence
        if self.patterns.REGISTRY_RUN.search(s):
            matches.append(
                StringMatch(
                    string=s[:100],
                    pattern_type="registry_run",
                    score=scores.get("registry_run", 15),
                    context="Registry Run key - persistence mechanism",
                )
            )

        if self.patterns.REGISTRY_SERVICES.search(s):
            matches.append(
                StringMatch(
                    string=s[:100],
                    pattern_type="registry_services",
                    score=scores.get("registry_run", 15),
                    context="Services registry key - persistence mechanism",
                )
            )

        if self.patterns.STARTUP_FOLDER.search(s):
            matches.append(
                StringMatch(
                    string=s[:100],
                    pattern_type="startup_folder",
                    score=scores.get("registry_run", 15),
                    context="Startup folder - persistence mechanism",
                )
            )

        # Base64 blobs (potential payloads)
        if len(s) > 100 and self.patterns.BASE64_BLOB.fullmatch(s):
            # Verify it's valid base64
            if self._is_valid_base64(s):
                matches.append(
                    StringMatch(
                        string=s[:50] + "..." + s[-20:],
                        pattern_type="base64_blob",
                        score=scores.get("base64_blob", 10),
                        context=f"Large Base64 blob ({len(s)} chars) - possible encoded payload",
                    )
                )

        return matches

    def _is_valid_base64(self, s: str) -> bool:
        """Check if string is valid base64"""
        try:
            decoded = base64.b64decode(s)
            # Check if decoded content has some printable characters
            printable = sum(1 for b in decoded if 32 <= b <= 126)
            return printable / len(decoded) > 0.1 if decoded else False
        except:
            return False

    def _is_interesting(self, s: str) -> bool:
        """Check if string is interesting (noteworthy but not necessarily malicious)"""
        interesting_keywords = [
            "debug",
            "error",
            "exception",
            "failed",
            "success",
            "admin",
            "root",
            "system",
            "user",
            "connect",
            "download",
            "upload",
            "send",
            "receive",
            "encrypt",
            "decrypt",
            "key",
            "password",
            "token",
            "inject",
            "hook",
            "patch",
            "bypass",
            "antivirus",
            "firewall",
            "sandbox",
            "virtual",
        ]

        s_lower = s.lower()
        return any(kw in s_lower for kw in interesting_keywords) and len(s) > 10

    def _generate_warnings(
        self,
        suspicious: List[StringMatch],
        urls: List[str],
        ips: List[str],
        registry: List[str],
    ) -> List[str]:
        """Generate human-readable warnings from findings"""
        warnings = []

        # Group suspicious strings by type
        by_type = defaultdict(list)
        for match in suspicious:
            by_type[match.pattern_type].append(match)

        if "shadow_delete" in by_type:
            warnings.append(
                "🔴 CRITICAL: Shadow copy deletion commands detected (ransomware indicator)"
            )

        if "ransomware_note" in by_type or "ransomware_extension" in by_type:
            warnings.append("🔴 CRITICAL: Ransomware-related strings detected")

        if "disable_defender" in by_type or "amsi_bypass" in by_type:
            warnings.append("🔴 Security software evasion techniques detected")

        if "powershell_encoded" in by_type:
            warnings.append("⚠️ Encoded PowerShell commands found")

        if "password_harvest" in by_type or "crypto_wallet" in by_type:
            warnings.append("⚠️ Credential/wallet theft indicators detected")

        if "keylogger_indicator" in by_type:
            warnings.append("⚠️ Keylogger/input monitoring indicators detected")

        if "registry_run" in by_type or "startup_folder" in by_type:
            warnings.append("⚠️ Persistence mechanisms detected")

        if len(urls) > 10:
            warnings.append(
                f"⚠️ {len(urls)} URLs found - possible C2 or download sources"
            )

        if ips:
            # Filter out common private/localhost IPs
            external_ips = [
                ip
                for ip in ips
                if not ip.startswith(("10.", "192.168.", "172.16.", "127.", "0."))
            ]
            if external_ips:
                warnings.append(f"⚠️ {len(external_ips)} external IP addresses found")

        return warnings
