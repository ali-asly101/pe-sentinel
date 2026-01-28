"""
Analysis engine wrapper for web API
Simplifies analysis calls from Flask

Updated to include:
- MITRE ATT&CK technique mapping
- String analysis integration
- Configurable thresholds
- Threat attribution scoring
- Export analysis
"""

from pathlib import Path
import sys
from typing import Optional, Dict, List

# Add reWebapp root to path (go up from backend -> pe-sentinel-web -> reWebapp)
ROOT_DIR = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from core.config import AnalysisConfig, DEFAULT_CONFIG
from core.pe_parser import PEAnalyzer
from core.analyzers import SectionAnalyzer, SectionAnalysis, PackerDetector
from core.string_analyzer import StringAnalyzer
from core.sentinel.extractors import FeatureExtractor
from core.sentinel.correlators import CorrelationEngine
from core.sentinel.verdict_engine import VerdictEngine
from core.sentinel.mitre_mapper import MitreMapper

# Optional YARA support
try:
    from core.yara_scanner import YaraScanner, YARA_AVAILABLE
except ImportError:
    YARA_AVAILABLE = False
    YaraScanner = None


class BinaryAnalyzer:
    """Unified analyzer for PE files with full feature set"""

    def __init__(self, filepath: str, config: AnalysisConfig = None):
        self.filepath = filepath
        self.config = config or DEFAULT_CONFIG
        self.pe_analyzer = PEAnalyzer(filepath)

    def analyze(self, include_strings: bool = True, include_yara: bool = True) -> dict:
        """
        Perform complete analysis with all available engines.

        Args:
            include_strings: Run string analysis (adds ~100ms)
            include_yara: Run YARA scanning if available (adds ~50ms)

        Returns:
            Comprehensive results dict with:
            - metadata: File info
            - scores: Structural, behavioral, overall with attribution
            - sections: Detailed section analysis
            - features: IAT, UI, trust signals, exports
            - capabilities: Detected malicious capabilities
            - mitre: MITRE ATT&CK mappings
            - strings: Suspicious string findings
            - yara: YARA rule matches
            - verdict: Final assessment with recommendations
        """
        # ============================================
        # Phase 1: Structural Analysis
        # ============================================
        sections = self.pe_analyzer.get_sections()
        imports = self.pe_analyzer.get_imports()
        metadata = self.pe_analyzer.get_metadata()

        # Packer detection
        packer_info = PackerDetector.analyze_packing_indicators(sections, self.config)

        # Section analysis with segment-level entropy
        section_analyzer = SectionAnalyzer(self.config)
        section_analyses = []
        section_objs = []  # For correlation engine

        for section in sections:
            analysis = section_analyzer.analyze_section(section)

            section_analyses.append(
                {
                    "name": analysis.name,
                    "entropy": analysis.entropy,
                    "entropy_status": analysis.entropy_status,
                    "size_ratio": analysis.size_ratio,
                    "permissions": analysis.permissions,
                    "suspicion_score": analysis.suspicion_score,
                    "suspicion_level": analysis.suspicion_level,
                    "warnings": analysis.warnings,
                    "is_suspicious": analysis.is_suspicious,
                    "segment_analysis": analysis.segment_analysis,
                    "virtual_size": section["virtual_size"],
                    "raw_size": section["raw_size"],
                }
            )

            # Build SectionAnalysis objects for correlation
            section_objs.append(
                SectionAnalysis(
                    name=analysis.name,
                    entropy=analysis.entropy,
                    entropy_status=analysis.entropy_status,
                    size_ratio=analysis.size_ratio,
                    size_status="",
                    permissions=analysis.permissions,
                    permission_status="",
                    suspicion_score=analysis.suspicion_score,
                    suspicion_level=analysis.suspicion_level,
                    warnings=analysis.warnings,
                    is_suspicious=analysis.is_suspicious,
                    segment_analysis=analysis.segment_analysis,
                )
            )

        structural_score = (
            max(s["suspicion_score"] for s in section_analyses)
            if section_analyses
            else 0
        )

        # ============================================
        # Phase 2: String Analysis
        # ============================================
        string_analysis = None
        string_results = {
            "total_strings": 0,
            "suspicious_count": 0,
            "urls": [],
            "ip_addresses": [],
            "suspicious_patterns": [],
            "score": 0,
        }

        if include_strings:
            try:
                string_analyzer = StringAnalyzer(self.config)
                string_analysis = string_analyzer.analyze(self.pe_analyzer.raw_data)

                string_results = {
                    "total_strings": string_analysis.total_strings,
                    "ascii_count": string_analysis.ascii_count,
                    "unicode_count": string_analysis.unicode_count,
                    "suspicious_count": len(string_analysis.suspicious_strings),
                    "urls": string_analysis.urls[:20],  # Limit for response size
                    "ip_addresses": string_analysis.ip_addresses[:10],
                    "file_paths": string_analysis.file_paths[:10],
                    "registry_keys": string_analysis.registry_keys[:10],
                    "suspicious_patterns": [
                        {
                            "string": match.string[:100],  # Truncate long strings
                            "type": match.pattern_type,
                            "score": match.score,
                            "context": match.context,
                        }
                        for match in string_analysis.suspicious_strings[:20]
                    ],
                    "score": string_analysis.suspicious_score,
                    "warnings": string_analysis.warnings,
                }
            except Exception as e:
                string_results["error"] = str(e)

        # ============================================
        # Phase 3: YARA Scanning
        # ============================================
        yara_results = {
            "available": YARA_AVAILABLE,
            "matches": [],
            "total_score": 0,
        }

        if include_yara and YARA_AVAILABLE and self.config.yara.enabled:
            try:
                yara_scanner = YaraScanner(self.config)
                yara_result = yara_scanner.scan(self.filepath)

                if yara_result.scanned:
                    yara_results = {
                        "available": True,
                        "scanned": True,
                        "matches": [
                            {
                                "rule": match.rule,
                                "namespace": match.namespace,
                                "tags": match.tags,
                                "score": match.score,
                            }
                            for match in yara_result.matches
                        ],
                        "total_score": yara_result.total_score,
                        "warnings": yara_result.warnings,
                    }
            except Exception as e:
                yara_results["error"] = str(e)

        # ============================================
        # Phase 4: Behavioral Analysis
        # ============================================
        extractor = FeatureExtractor(self.filepath, self.config)
        features = extractor.extract_all()

        # Correlation engine
        correlation_engine = CorrelationEngine(self.config)
        correlation = correlation_engine.correlate(features, section_objs)

        # ============================================
        # Phase 5: Final Verdict
        # ============================================
        verdict_engine = VerdictEngine(self.config)
        verdict = verdict_engine.generate_verdict(
            features,
            correlation,
            structural_score=structural_score,
            string_analysis=string_analysis,
        )

        # Add YARA boost to final score
        if yara_results.get("total_score", 0) > 0:
            yara_boost = min(20, yara_results["total_score"] // 5)
            verdict["final_score"] = min(100, verdict["final_score"] + yara_boost)

            # Update threat level if needed
            if verdict["final_score"] >= self.config.scoring.critical_threshold:
                verdict["threat_level"] = "CRITICAL"
            elif verdict["final_score"] >= self.config.scoring.high_threshold:
                verdict["threat_level"] = "HIGH"

        # ============================================
        # Phase 6: MITRE ATT&CK Mapping
        # ============================================
        mitre_techniques = MitreMapper.map_capabilities(correlation["capabilities"])
        mitre_matrix = MitreMapper.generate_attack_matrix(mitre_techniques)

        # ============================================
        # Calculate Overall Score
        # ============================================
        behavioral_score = verdict["final_score"]
        has_signature = features["trust_signals"]["has_signature"]
        has_bulk = features["trust_signals"]["has_bulk"]

        # Weighted scoring based on trust signals
        if has_signature and has_bulk:
            overall_score = int(structural_score * 0.3 + behavioral_score * 0.7)
        elif has_signature:
            overall_score = int(structural_score * 0.4 + behavioral_score * 0.6)
        else:
            overall_score = max(structural_score, behavioral_score)

        # Threat level determination
        threat_level, threat_color = self._get_threat_level(overall_score)

        # ============================================
        # Build Response
        # ============================================
        return {
            "metadata": metadata,
            "packer_info": {
                "detected_packers": packer_info.get("detected_packers", []),
                "is_likely_packed": packer_info.get("is_likely_packed", False),
                "packing_score": packer_info.get("packing_score", 0),
            },
            "scores": {
                "structural": structural_score,
                "behavioral": behavioral_score,
                "string": string_results.get("score", 0),
                "yara": yara_results.get("total_score", 0),
                "overall": overall_score,
                "threat_level": threat_level,
                "threat_color": threat_color,
                "attribution": verdict.get("attribution", {}),
                "primary_driver": verdict.get("primary_driver", "Unknown"),
            },
            "sections": section_analyses,
            "features": {
                "iat_analysis": {
                    "total_imports": features["iat_analysis"]["total_imports"],
                    "dll_count": features["iat_analysis"]["dll_count"],
                    "ordinal_count": features["iat_analysis"]["ordinal_count"],
                    "ordinal_ratio": features["iat_analysis"]["ordinal_ratio"],
                    "has_critical_loaders": features["iat_analysis"][
                        "has_critical_loaders"
                    ],
                    "is_minimal": features["iat_analysis"].get("is_minimal", False),
                    "is_ordinal_heavy": features["iat_analysis"].get(
                        "is_ordinal_heavy", False
                    ),
                },
                "ui_indicators": {
                    "has_ui_dlls": features["ui_indicators"]["has_ui_dlls"],
                    "has_network_dlls": features["ui_indicators"]["has_network_dlls"],
                    "has_crypto_dlls": features["ui_indicators"]["has_crypto_dlls"],
                    "is_headless": features["ui_indicators"]["is_headless"],
                    "subsystem": features["ui_indicators"]["subsystem"],
                    "subsystem_name": features["ui_indicators"]["subsystem_name"],
                },
                "trust_signals": {
                    "has_signature": features["trust_signals"]["has_signature"],
                    "has_version_info": features["trust_signals"]["has_version_info"],
                    "has_manifest": features["trust_signals"]["has_manifest"],
                    "has_resources": features["trust_signals"]["has_resources"],
                    "trust_level": features["trust_signals"]["trust_level"],
                    "trust_score": features["trust_signals"]["trust_score"],
                },
                "export_analysis": {
                    "has_exports": features["export_analysis"]["has_exports"],
                    "export_count": features["export_analysis"]["export_count"],
                    "forwarder_count": features["export_analysis"].get(
                        "forwarder_count", 0
                    ),
                    "is_suspicious": features["export_analysis"]["is_suspicious"],
                    "suspicion_reasons": features["export_analysis"].get(
                        "suspicion_reasons", []
                    ),
                },
            },
            "capabilities": [
                {
                    "capability": cap["capability"],
                    "description": cap["description"],
                    "score": cap["final_score"],
                    "matched_apis": cap["matched_apis"],
                    "match_count": cap["match_count"],
                    "is_obfuscated": cap["is_obfuscated"],
                    "obfuscation_multiplier": cap.get("obfuscation_multiplier", 1.0),
                    "confidence": cap.get("confidence", 0.0),
                }
                for cap in correlation["capabilities"]
            ],
            "mitre": {
                "techniques": mitre_techniques,
                "matrix": mitre_matrix,
                "total_techniques": len(mitre_techniques),
            },
            "strings": string_results,
            "yara": yara_results,
            "verdict": {
                "final_score": verdict["final_score"],
                "threat_level": verdict["threat_level"],
                "reasons": verdict["reasons"],
                "is_likely_malicious": verdict["is_likely_malicious"],
                "recommendations": verdict.get("recommendations", []),
                "trust_multiplier": verdict.get("trust_multiplier", 1.0),
            },
        }

    def _get_threat_level(self, score: int) -> tuple:
        """Determine threat level and color from score"""
        cfg = self.config.scoring

        if score >= cfg.critical_threshold:
            return "CRITICAL", "#dc3545"
        elif score >= cfg.high_threshold:
            return "HIGH", "#fd7e14"
        elif score >= cfg.medium_threshold:
            return "MEDIUM", "#ffc107"
        elif score >= cfg.low_threshold:
            return "LOW", "#28a745"
        else:
            return "CLEAN", "#20c997"

    def analyze_quick(self) -> dict:
        """
        Quick analysis without string/YARA scanning.
        Faster for real-time previews.
        """
        return self.analyze(include_strings=False, include_yara=False)

    def get_iocs(self) -> dict:
        """
        Extract Indicators of Compromise only.
        Useful for threat intel integration.
        """
        string_analyzer = StringAnalyzer(self.config)
        string_analysis = string_analyzer.analyze(self.pe_analyzer.raw_data)

        return {
            "urls": string_analysis.urls,
            "ip_addresses": string_analysis.ip_addresses,
            "file_paths": string_analysis.file_paths,
            "registry_keys": string_analysis.registry_keys,
            "domains": self._extract_domains(string_analysis.urls),
        }

    def _extract_domains(self, urls: List[str]) -> List[str]:
        """Extract unique domains from URLs"""
        import re

        domains = set()
        for url in urls:
            match = re.search(r"https?://([^/]+)", url)
            if match:
                domains.add(match.group(1))
        return list(domains)


# Convenience function for simple usage
def analyze_file(filepath: str, config: AnalysisConfig = None) -> dict:
    """
    Analyze a PE file and return comprehensive results.

    Args:
        filepath: Path to PE file
        config: Optional configuration

    Returns:
        Analysis results dictionary
    """
    analyzer = BinaryAnalyzer(filepath, config)
    return analyzer.analyze()
