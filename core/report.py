"""
Report Generation Module
Structured reporting for PE analysis results.
Supports multiple output formats: JSON, SARIF, HTML, Markdown.
"""

import json
import hashlib
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from pathlib import Path

from .string_analyzer import StringAnalysisResult
from .yara_scanner import YaraScanResult


@dataclass
class SectionInfo:
    """Section summary for report"""

    name: str
    entropy: float
    size_ratio: float
    permissions: str
    suspicion_score: int
    suspicion_level: str
    warnings: List[str]


@dataclass
class CapabilityInfo:
    """Capability summary for report"""

    name: str
    description: str
    score: int
    confidence: float
    matched_apis: List[str]


@dataclass
class IOCInfo:
    """Indicators of Compromise"""

    urls: List[str]
    ip_addresses: List[str]
    file_paths: List[str]
    registry_keys: List[str]


@dataclass
class ThreatReport:
    """Complete threat analysis report"""

    # File identification
    filepath: str
    filename: str
    sha256: str
    md5: str
    file_size: int

    # Analysis metadata
    analysis_timestamp: str
    analyzer_version: str

    # Scores
    overall_score: int
    structural_score: int
    behavioral_score: int
    string_score: int
    yara_score: int

    # Threat assessment
    threat_level: str
    is_likely_malicious: bool
    primary_driver: str
    attribution: Dict[str, int]

    # Detailed findings
    sections: List[SectionInfo]
    capabilities: List[CapabilityInfo]
    suspicious_strings: List[Dict]
    yara_matches: List[Dict]
    iocs: IOCInfo

    # Trust signals
    is_signed: bool
    has_version_info: bool
    trust_level: str

    # Recommendations
    recommendations: List[str]
    warnings: List[str]

    # Raw data (optional, for detailed reports)
    raw_verdict: Optional[Dict] = None
    raw_features: Optional[Dict] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Export as JSON string"""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def save_json(self, filepath: str):
        """Save report to JSON file"""
        with open(filepath, "w") as f:
            f.write(self.to_json())

    def to_sarif(self) -> Dict:
        """
        Export as SARIF format for CI/CD integration.
        SARIF = Static Analysis Results Interchange Format
        """
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "PE-Sentinel",
                            "version": self.analyzer_version,
                            "informationUri": "https://github.com/yourusername/pe-sentinel",
                            "rules": self._generate_sarif_rules(),
                        }
                    },
                    "results": self._generate_sarif_results(),
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": self.analysis_timestamp,
                        }
                    ],
                }
            ],
        }
        return sarif

    def _generate_sarif_rules(self) -> List[Dict]:
        """Generate SARIF rule definitions"""
        rules = []

        # Add rule for each detected capability
        for cap in self.capabilities:
            rules.append(
                {
                    "id": f"PE-{cap.name.upper()}",
                    "name": cap.description,
                    "shortDescription": {"text": cap.description},
                    "defaultConfiguration": {
                        "level": "warning" if cap.score < 40 else "error"
                    },
                }
            )

        return rules

    def _generate_sarif_results(self) -> List[Dict]:
        """Generate SARIF results"""
        results = []

        for cap in self.capabilities:
            results.append(
                {
                    "ruleId": f"PE-{cap.name.upper()}",
                    "level": "warning" if cap.score < 40 else "error",
                    "message": {
                        "text": f"{cap.description}: Score {cap.score}, Confidence {cap.confidence*100:.0f}%"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": self.filename}
                            }
                        }
                    ],
                }
            )

        return results

    def to_markdown(self) -> str:
        """Export as Markdown report"""
        md = []

        # Header
        md.append(f"# PE Analysis Report: {self.filename}")
        md.append(f"\n**Analysis Date:** {self.analysis_timestamp}")
        md.append(f"**Analyzer Version:** {self.analyzer_version}")

        # Summary
        md.append("\n## Executive Summary")
        md.append(f"\n| Metric | Value |")
        md.append(f"|--------|-------|")
        md.append(f"| **Threat Level** | {self._threat_emoji()} {self.threat_level} |")
        md.append(f"| **Overall Score** | {self.overall_score}/100 |")
        md.append(f"| **Primary Driver** | {self.primary_driver} |")
        md.append(
            f"| **Likely Malicious** | {'Yes' if self.is_likely_malicious else 'No'} |"
        )

        # File Info
        md.append("\n## File Information")
        md.append(f"\n- **Path:** `{self.filepath}`")
        md.append(f"- **Size:** {self.file_size:,} bytes")
        md.append(f"- **SHA256:** `{self.sha256}`")
        md.append(f"- **MD5:** `{self.md5}`")
        md.append(f"- **Signed:** {'Yes' if self.is_signed else 'No'}")

        # Score Breakdown
        md.append("\n## Score Breakdown")
        md.append(f"\n| Component | Score |")
        md.append(f"|-----------|-------|")
        md.append(f"| Structural | {self.structural_score} |")
        md.append(f"| Behavioral | {self.behavioral_score} |")
        md.append(f"| Strings | {self.string_score} |")
        md.append(f"| YARA | {self.yara_score} |")

        # Attribution
        md.append("\n### Threat Attribution")
        for category, score in self.attribution.items():
            bar = "█" * (score // 5)
            md.append(f"- **{category}:** {score} {bar}")

        # Capabilities
        if self.capabilities:
            md.append("\n## Detected Capabilities")
            for cap in self.capabilities:
                md.append(f"\n### {cap.description}")
                md.append(f"- **Score:** {cap.score}")
                md.append(f"- **Confidence:** {cap.confidence*100:.0f}%")
                md.append(f"- **Matched APIs:** {', '.join(cap.matched_apis[:5])}")

        # Sections
        md.append("\n## Section Analysis")
        md.append(f"\n| Section | Entropy | Ratio | Permissions | Score | Level |")
        md.append(f"|---------|---------|-------|-------------|-------|-------|")
        for sec in self.sections:
            md.append(
                f"| {sec.name} | {sec.entropy:.2f} | {sec.size_ratio:.2f} | "
                f"{sec.permissions} | {sec.suspicion_score} | {sec.suspicion_level} |"
            )

        # IOCs
        if self.iocs.urls or self.iocs.ip_addresses:
            md.append("\n## Indicators of Compromise (IOCs)")

            if self.iocs.urls:
                md.append("\n### URLs")
                for url in self.iocs.urls[:20]:
                    md.append(f"- `{url}`")

            if self.iocs.ip_addresses:
                md.append("\n### IP Addresses")
                for ip in self.iocs.ip_addresses[:10]:
                    md.append(f"- `{ip}`")

        # Warnings
        if self.warnings:
            md.append("\n## Warnings")
            for warning in self.warnings:
                md.append(f"- {warning}")

        # Recommendations
        md.append("\n## Recommendations")
        for rec in self.recommendations:
            md.append(f"- {rec}")

        return "\n".join(md)

    def _threat_emoji(self) -> str:
        """Get emoji for threat level"""
        emojis = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "CLEAN": "✅",
        }
        return emojis.get(self.threat_level, "❓")

    def to_html(self) -> str:
        """Export as HTML report"""
        # Convert markdown to basic HTML
        md = self.to_markdown()

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>PE Analysis Report: {self.filename}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
               max-width: 1200px; margin: 0 auto; padding: 20px; background: #1a1a2e; color: #eee; }}
        h1 {{ color: #00d9ff; border-bottom: 2px solid #00d9ff; padding-bottom: 10px; }}
        h2 {{ color: #ff6b6b; margin-top: 30px; }}
        h3 {{ color: #ffd93d; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #444; padding: 10px; text-align: left; }}
        th {{ background: #2d2d44; }}
        tr:nth-child(even) {{ background: #252538; }}
        code {{ background: #2d2d44; padding: 2px 6px; border-radius: 4px; color: #00d9ff; }}
        .critical {{ color: #ff4444; font-weight: bold; }}
        .high {{ color: #ff8c00; font-weight: bold; }}
        .medium {{ color: #ffd700; }}
        .low {{ color: #90ee90; }}
        .clean {{ color: #00ff00; }}
        .score-bar {{ background: #333; height: 20px; border-radius: 10px; overflow: hidden; }}
        .score-fill {{ height: 100%; background: linear-gradient(90deg, #00ff00, #ffff00, #ff0000); }}
    </style>
</head>
<body>
    <h1>{self._threat_emoji()} PE Analysis Report: {self.filename}</h1>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Threat Level:</strong> <span class="{self.threat_level.lower()}">{self.threat_level}</span></p>
        <p><strong>Overall Score:</strong> {self.overall_score}/100</p>
        <div class="score-bar">
            <div class="score-fill" style="width: {self.overall_score}%"></div>
        </div>
        <p><strong>Primary Driver:</strong> {self.primary_driver}</p>
        <p><strong>Analysis Time:</strong> {self.analysis_timestamp}</p>
    </div>
    
    <h2>File Information</h2>
    <table>
        <tr><td>Filename</td><td><code>{self.filename}</code></td></tr>
        <tr><td>Size</td><td>{self.file_size:,} bytes</td></tr>
        <tr><td>SHA256</td><td><code>{self.sha256}</code></td></tr>
        <tr><td>MD5</td><td><code>{self.md5}</code></td></tr>
        <tr><td>Signed</td><td>{'✅ Yes' if self.is_signed else '❌ No'}</td></tr>
    </table>
    
    <h2>Score Breakdown</h2>
    <table>
        <tr><th>Component</th><th>Score</th></tr>
        <tr><td>Structural</td><td>{self.structural_score}</td></tr>
        <tr><td>Behavioral</td><td>{self.behavioral_score}</td></tr>
        <tr><td>Strings</td><td>{self.string_score}</td></tr>
        <tr><td>YARA</td><td>{self.yara_score}</td></tr>
    </table>
    
    <h2>Recommendations</h2>
    <ul>
        {''.join(f'<li>{rec}</li>' for rec in self.recommendations)}
    </ul>
</body>
</html>"""
        return html


class ReportGenerator:
    """Generate reports from analysis results"""

    VERSION = "2.0.0"

    @classmethod
    def generate(
        cls,
        filepath: str,
        verdict: Dict,
        features: Dict,
        section_analyses: List,
        string_analysis: Optional[StringAnalysisResult] = None,
        yara_result: Optional[YaraScanResult] = None,
    ) -> ThreatReport:
        """
        Generate a comprehensive threat report.

        Args:
            filepath: Path to analyzed file
            verdict: From VerdictEngine
            features: From FeatureExtractor
            section_analyses: From SectionAnalyzer
            string_analysis: From StringAnalyzer
            yara_result: From YaraScanner

        Returns:
            ThreatReport instance
        """
        # Calculate file hashes
        with open(filepath, "rb") as f:
            data = f.read()
            sha256 = hashlib.sha256(data).hexdigest()
            md5 = hashlib.md5(data).hexdigest()

        # Build section info
        sections = []
        for analysis in section_analyses:
            sections.append(
                SectionInfo(
                    name=analysis.name,
                    entropy=analysis.entropy,
                    size_ratio=analysis.size_ratio,
                    permissions=analysis.permissions,
                    suspicion_score=analysis.suspicion_score,
                    suspicion_level=analysis.suspicion_level,
                    warnings=analysis.warnings,
                )
            )

        # Build capability info
        capabilities = []
        for cap in verdict.get("correlation", {}).get("capabilities", []):
            capabilities.append(
                CapabilityInfo(
                    name=cap["capability"],
                    description=cap["description"],
                    score=cap["final_score"],
                    confidence=cap["confidence"],
                    matched_apis=cap["matched_apis"],
                )
            )

        # Build IOCs
        iocs = IOCInfo(
            urls=string_analysis.urls if string_analysis else [],
            ip_addresses=string_analysis.ip_addresses if string_analysis else [],
            file_paths=string_analysis.file_paths[:20] if string_analysis else [],
            registry_keys=string_analysis.registry_keys[:20] if string_analysis else [],
        )

        # Collect all warnings
        warnings = []
        if string_analysis:
            warnings.extend(string_analysis.warnings)
        if yara_result:
            warnings.extend(yara_result.warnings)

        # Suspicious strings for report
        suspicious_strings = []
        if string_analysis:
            for match in string_analysis.suspicious_strings[:30]:
                suspicious_strings.append(
                    {
                        "string": match.string,
                        "type": match.pattern_type,
                        "score": match.score,
                        "context": match.context,
                    }
                )

        # YARA matches for report
        yara_matches = []
        if yara_result and yara_result.matches:
            for match in yara_result.matches:
                yara_matches.append(
                    {
                        "rule": match.rule,
                        "namespace": match.namespace,
                        "tags": match.tags,
                        "score": match.score,
                    }
                )

        # Calculate structural score
        structural_score = (
            max(a.suspicion_score for a in section_analyses) if section_analyses else 0
        )

        return ThreatReport(
            filepath=filepath,
            filename=Path(filepath).name,
            sha256=sha256,
            md5=md5,
            file_size=features.get("file_size", 0),
            analysis_timestamp=datetime.utcnow().isoformat(),
            analyzer_version=cls.VERSION,
            overall_score=verdict["final_score"],
            structural_score=structural_score,
            behavioral_score=verdict["final_score"],
            string_score=verdict.get("string_score", 0),
            yara_score=yara_result.total_score if yara_result else 0,
            threat_level=verdict["threat_level"],
            is_likely_malicious=verdict["is_likely_malicious"],
            primary_driver=verdict["primary_driver"],
            attribution=verdict["attribution"],
            sections=sections,
            capabilities=capabilities,
            suspicious_strings=suspicious_strings,
            yara_matches=yara_matches,
            iocs=iocs,
            is_signed=features["trust_signals"]["has_signature"],
            has_version_info=features["trust_signals"]["has_version_info"],
            trust_level=features["trust_signals"]["trust_level"],
            recommendations=verdict.get("recommendations", []),
            warnings=warnings,
            raw_verdict=verdict,
            raw_features=features,
        )
