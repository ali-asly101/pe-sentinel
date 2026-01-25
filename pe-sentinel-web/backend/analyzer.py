"""
Analysis engine wrapper for web API
Simplifies analysis calls from Flask
"""

from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.pe_parser import PEAnalyzer
from core.analyzers import SectionAnalyzer, PackerDetector
from core.sentinel.extractors import FeatureExtractor
from core.sentinel.correlators import CorrelationEngine
from core.sentinel.verdict_engine import VerdictEngine


class BinaryAnalyzer:
    """Unified analyzer for PE files"""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.pe_analyzer = PEAnalyzer(filepath)

    def analyze(self) -> dict:
        """
        Perform complete analysis
        Returns comprehensive results dict
        """
        # Parse PE
        sections = self.pe_analyzer.get_sections()
        imports = self.pe_analyzer.get_imports()
        metadata = self.pe_analyzer.get_metadata()

        # Section analysis
        section_analyses = []
        for section in sections:
            analysis = SectionAnalyzer.analyze_section(section)

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

        section_max_score = (
            max(s["suspicion_score"] for s in section_analyses)
            if section_analyses
            else 0
        )

        # Behavioral analysis
        extractor = FeatureExtractor(self.filepath)
        features = extractor.extract_all()

        # Convert to SectionAnalysis objects for correlation
        from core.analyzers import SectionAnalysis

        section_objs = [
            SectionAnalysis(
                name=sa["name"],
                entropy=sa["entropy"],
                entropy_status=sa["entropy_status"],
                size_ratio=sa["size_ratio"],
                size_status="",
                permissions=sa["permissions"],
                permission_status="",
                suspicion_score=sa["suspicion_score"],
                suspicion_level=sa["suspicion_level"],
                warnings=sa["warnings"],
                is_suspicious=sa["is_suspicious"],
                segment_analysis=sa["segment_analysis"],
            )
            for sa in section_analyses
        ]

        correlation = CorrelationEngine.correlate(features, section_objs)
        verdict = VerdictEngine.generate_verdict(features, correlation)

        # Calculate overall score
        structural_score = section_max_score
        behavioral_score = verdict["final_score"]
        has_signature = features["trust_signals"]["has_signature"]
        has_bulk = features["trust_signals"]["has_bulk"]

        if has_signature and has_bulk:
            overall_score = int(structural_score * 0.3 + behavioral_score * 0.7)
        elif has_signature:
            overall_score = int(structural_score * 0.4 + behavioral_score * 0.6)
        else:
            overall_score = max(structural_score, behavioral_score)

        # Threat level
        if overall_score >= 80:
            threat_level = "CRITICAL"
            threat_color = "#dc3545"
        elif overall_score >= 60:
            threat_level = "HIGH"
            threat_color = "#fd7e14"
        elif overall_score >= 40:
            threat_level = "MEDIUM"
            threat_color = "#ffc107"
        elif overall_score >= 20:
            threat_level = "LOW"
            threat_color = "#28a745"
        else:
            threat_level = "CLEAN"
            threat_color = "#20c997"

        return {
            "metadata": metadata,
            "scores": {
                "structural": structural_score,
                "behavioral": behavioral_score,
                "overall": overall_score,
                "threat_level": threat_level,
                "threat_color": threat_color,
            },
            "sections": section_analyses,
            "features": {
                "iat_analysis": {
                    "total_imports": features["iat_analysis"]["total_imports"],
                    "dll_count": features["iat_analysis"]["dll_count"],
                    "ordinal_count": features["iat_analysis"]["ordinal_count"],
                    "ordinal_ratio": features["iat_analysis"]["ordinal_ratio"],
                    "has_critical_loaders": len(
                        features["iat_analysis"]["critical_loaders"]
                    )
                    > 0,
                },
                "ui_indicators": features["ui_indicators"],
                "trust_signals": features["trust_signals"],
            },
            "capabilities": [
                {
                    "description": cap["description"],
                    "score": cap["final_score"],
                    "matched_apis": cap["matched_apis"],
                    "is_obfuscated": cap["is_obfuscated"],
                }
                for cap in correlation["capabilities"]
            ],
            "verdict": {
                "reasons": verdict["reasons"],
                "is_likely_malicious": verdict["is_likely_malicious"],
            },
        }
