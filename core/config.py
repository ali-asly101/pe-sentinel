"""
PE-Sentinel Configuration
Centralized configuration for all analysis parameters.
Allows easy tuning without modifying code.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Tuple
import json
from pathlib import Path


@dataclass
class EntropyConfig:
    """Entropy analysis thresholds"""

    critical: float = 7.5  # Very high - likely packed/encrypted
    high: float = 7.0  # High - possible obfuscation
    empty: float = 1.0  # Near-zero - padding or uninitialized

    # Section-specific expected ranges (min, max)
    section_ranges: Dict[str, Tuple[float, float]] = field(
        default_factory=lambda: {
            ".text": (4.5, 6.5),
            ".data": (3.0, 6.0),
            ".rdata": (4.0, 6.5),
            ".bss": (0.0, 1.0),
            ".rsrc": (5.0, 7.5),
            ".reloc": (2.0, 5.0),
        }
    )

    # Segment analysis
    chunk_size: int = 4096  # Bytes per chunk for segment analysis
    variance_threshold: float = 3.0  # Max-min entropy difference for anomaly


@dataclass
class SizeConfig:
    """Size-based thresholds"""

    min_file_size_kb: int = 10  # Files smaller than this are suspicious
    expansion_ratio_moderate: float = 2.0  # Virtual/raw ratio warning
    expansion_ratio_high: float = 3.0  # High expansion
    expansion_ratio_very_high: float = 5.0  # Very high expansion
    expansion_ratio_critical: float = 10.0  # Critical expansion

    # Section-specific expected ratios (min, max)
    section_ratios: Dict[str, Tuple[float, float]] = field(
        default_factory=lambda: {
            ".text": (0.95, 1.05),
            ".data": (0.9, 2.0),
            ".rdata": (0.95, 1.1),
            ".bss": (1.0, float("inf")),
            ".rsrc": (0.9, 1.2),
            ".reloc": (0.9, 1.5),
        }
    )


@dataclass
class ImportConfig:
    """Import analysis thresholds"""

    ordinal_ratio_suspicious: float = 0.3  # >30% ordinal imports is suspicious
    minimal_import_count: int = 5  # Very few imports suggests manual resolution

    # Critical loader functions (used for manual API resolution)
    critical_loaders: List[str] = field(
        default_factory=lambda: [
            "GetProcAddress",
            "LoadLibraryA",
            "LoadLibraryW",
            "LoadLibraryExA",
            "LoadLibraryExW",
            "LdrLoadDll",
            "LdrGetProcedureAddress",
        ]
    )


@dataclass
class TrustConfig:
    """Trust signal configuration"""

    # Trust reduction multipliers (1.0 = no reduction, 0.0 = full trust)
    signed_with_metadata: float = 0.5  # Signed + version info + manifest
    signed_only: float = 0.75  # Signed but missing other trust signals
    unsigned: float = 1.0  # No reduction

    # Trust signal weights
    signature_weight: int = 15
    version_info_weight: int = 10
    manifest_weight: int = 5
    resources_weight: int = 5


@dataclass
class ScoringConfig:
    """Scoring weights and caps"""

    # Maximum scores per category
    max_capability_score: int = 80
    max_structural_score: int = 100
    max_indiscrepancy_score: int = 50
    max_total_score: int = 100

    # Threat level thresholds
    critical_threshold: int = 80
    high_threshold: int = 60
    medium_threshold: int = 40
    low_threshold: int = 20

    # Obfuscation multiplier caps
    max_obfuscation_multiplier: float = 3.0

    # Correlation bonuses
    entropy_segment_correlation_bonus: int = 25  # Low overall + segment anomaly
    entropy_size_high_correlation_bonus: int = 20  # High entropy + high expansion
    entropy_size_moderate_correlation_bonus: int = 10


@dataclass
class StringAnalysisConfig:
    """String extraction and analysis configuration"""

    min_string_length: int = 4
    max_strings_to_analyze: int = 5000

    # Suspicious string pattern scores
    pattern_scores: Dict[str, int] = field(
        default_factory=lambda: {
            "url": 5,
            "ip_address": 5,
            "registry_run": 15,
            "powershell_encoded": 25,
            "powershell_exec": 15,
            "cmd_exec": 10,
            "shadow_delete": 30,
            "disable_defender": 25,
            "crypto_wallet": 20,
            "password_harvest": 15,
            "keylogger_indicator": 20,
            "ransomware_note": 35,
            "base64_blob": 10,
        }
    )


@dataclass
class YaraConfig:
    """YARA scanning configuration"""

    enabled: bool = True
    rules_directory: str = "rules/"
    timeout: int = 60  # seconds

    # Score multipliers for YARA matches by category
    category_scores: Dict[str, int] = field(
        default_factory=lambda: {
            "malware": 40,
            "ransomware": 50,
            "trojan": 45,
            "backdoor": 45,
            "rat": 45,
            "packer": 15,
            "crypter": 20,
            "suspicious": 10,
            "pup": 5,  # Potentially Unwanted Program
        }
    )


@dataclass
class AnalysisConfig:
    """Master configuration combining all sub-configs"""

    entropy: EntropyConfig = field(default_factory=EntropyConfig)
    size: SizeConfig = field(default_factory=SizeConfig)
    imports: ImportConfig = field(default_factory=ImportConfig)
    trust: TrustConfig = field(default_factory=TrustConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    strings: StringAnalysisConfig = field(default_factory=StringAnalysisConfig)
    yara: YaraConfig = field(default_factory=YaraConfig)

    def save(self, filepath: str):
        """Save configuration to JSON file"""

        def serialize(obj):
            if hasattr(obj, "__dataclass_fields__"):
                return {k: serialize(v) for k, v in obj.__dict__.items()}
            elif isinstance(obj, dict):
                return {k: serialize(v) for k, v in obj.items()}
            elif isinstance(obj, (list, tuple)):
                return [serialize(v) for v in obj]
            elif obj == float("inf"):
                return "inf"
            return obj

        with open(filepath, "w") as f:
            json.dump(serialize(self), f, indent=2)

    @classmethod
    def load(cls, filepath: str) -> "AnalysisConfig":
        """Load configuration from JSON file"""
        if not Path(filepath).exists():
            return cls()  # Return defaults if file doesn't exist

        with open(filepath, "r") as f:
            data = json.load(f)

        def deserialize_inf(obj):
            if isinstance(obj, dict):
                return {k: deserialize_inf(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [deserialize_inf(v) for v in obj]
            elif obj == "inf":
                return float("inf")
            return obj

        data = deserialize_inf(data)

        return cls(
            entropy=EntropyConfig(**data.get("entropy", {})),
            size=SizeConfig(**data.get("size", {})),
            imports=ImportConfig(**data.get("imports", {})),
            trust=TrustConfig(**data.get("trust", {})),
            scoring=ScoringConfig(**data.get("scoring", {})),
            strings=StringAnalysisConfig(**data.get("strings", {})),
            yara=YaraConfig(**data.get("yara", {})),
        )


# Global default configuration
DEFAULT_CONFIG = AnalysisConfig()


def get_config(config_path: str = None) -> AnalysisConfig:
    """Get configuration, loading from file if specified"""
    if config_path:
        return AnalysisConfig.load(config_path)
    return DEFAULT_CONFIG
