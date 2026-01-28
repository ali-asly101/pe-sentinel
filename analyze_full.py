#!/usr/bin/env python3
"""
PE-Sentinel v2.0 - Full PE Analysis Tool
Comprehensive static malware analysis with:
- Structural analysis (entropy, sections, permissions)
- Behavioral analysis (API capabilities, correlations)
- String analysis (suspicious patterns, IOCs)
- YARA scanning (rule-based detection)
- Trust signal evaluation
- Configurable thresholds
- Multiple report formats
"""

import sys
import argparse
from pathlib import Path
from typing import Optional

# Try GUI file picker, fallback to CLI
try:
    import tkinter as tk
    from tkinter import filedialog

    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

from core.config import AnalysisConfig, get_config
from core.pe_parser import PEAnalyzer
from core.analyzers import SectionAnalyzer, PackerDetector
from core.string_analyzer import StringAnalyzer
from core.yara_scanner import YaraScanner, YARA_AVAILABLE, create_sample_rules
from core.sentinel.extractors import FeatureExtractor
from core.sentinel.correlators import CorrelationEngine
from core.sentinel.verdict_engine import VerdictEngine
from core.report import ReportGenerator, ThreatReport


def select_file_gui() -> Optional[str]:
    """Open file dialog to select PE file"""
    if not GUI_AVAILABLE:
        return None

    root = tk.Tk()
    root.withdraw()

    filepath = filedialog.askopenfilename(
        title="Select a PE file to analyze",
        filetypes=[("Executable Files", "*.exe *.dll *.sys"), ("All Files", "*.*")],
    )

    return filepath if filepath else None


def print_banner():
    """Print PE-Sentinel banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║   ██████╗ ███████╗      ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██║
║   ██╔══██╗██╔════╝      ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║
║   ██████╔╝█████╗  █████╗███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║
║   ██╔═══╝ ██╔══╝  ╚════╝╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║
║   ██║     ███████╗      ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║
║   ╚═╝     ╚══════╝      ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝
║                                                                       ║
║                    Static Malware Analysis Tool v2.0                  ║
╚═══════════════════════════════════════════════════════════════════════╝
"""
    print(banner)


def analyze_file(
    filepath: str,
    config: AnalysisConfig = None,
    verbose: bool = True,
    output_format: str = None,
    output_path: str = None,
) -> ThreatReport:
    """
    Perform complete analysis on a PE file.

    Args:
        filepath: Path to PE file
        config: Analysis configuration
        verbose: Print progress to console
        output_format: Report format (json, md, html, sarif)
        output_path: Path to save report

    Returns:
        ThreatReport with all findings
    """
    config = config or AnalysisConfig()

    if verbose:
        print(f"\n{'='*70}")
        print(f"Analyzing: {Path(filepath).name}")
        print(f"{'='*70}\n")

    # ========================================
    # PHASE 1: Structural Analysis
    # ========================================
    if verbose:
        print("=" * 70)
        print("PHASE 1: STRUCTURAL ANALYSIS")
        print("=" * 70)

    pe_analyzer = PEAnalyzer(filepath)
    sections = pe_analyzer.get_sections()
    imports = pe_analyzer.get_imports()

    # Packer detection
    packer_info = PackerDetector.analyze_packing_indicators(sections, config)

    if verbose and packer_info["detected_packers"]:
        print(f"\n⚠️  Packers detected: {', '.join(packer_info['detected_packers'])}")

    # Section analysis
    section_analyzer = SectionAnalyzer(config)
    section_analyses = []
    suspicious_sections = []

    if verbose:
        print(f"\nSection Analysis:")
        print(
            f"{'Section':<12} {'Entropy':<8} {'Ratio':<8} {'Perms':<6} {'Score':<6} {'Level':<10}"
        )
        print("-" * 60)

    for section in sections:
        analysis = section_analyzer.analyze_section(section)
        section_analyses.append(analysis)

        if analysis.is_suspicious:
            suspicious_sections.append(analysis)

        if verbose:
            emoji_map = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🟢",
                "CLEAN": "✅",
            }
            emoji = emoji_map.get(analysis.suspicion_level, "")

            print(
                f"{analysis.name:<12} "
                f"{analysis.entropy:<8.2f} "
                f"{analysis.size_ratio:<8.2f} "
                f"{analysis.permissions:<6} "
                f"{analysis.suspicion_score:<6} "
                f"{emoji} {analysis.suspicion_level}"
            )

    structural_score = (
        max(a.suspicion_score for a in section_analyses) if section_analyses else 0
    )

    # Show warnings for suspicious sections
    if verbose and suspicious_sections:
        print(f"\n⚠️  Suspicious Sections:")
        for analysis in suspicious_sections:
            print(f"\n  {analysis.name} ({analysis.suspicion_score}/100):")
            for warning in analysis.warnings:
                print(f"    • {warning}")

    # ========================================
    # PHASE 2: String Analysis
    # ========================================
    if verbose:
        print("\n" + "=" * 70)
        print("PHASE 2: STRING ANALYSIS")
        print("=" * 70)

    string_analyzer = StringAnalyzer(config)
    string_analysis = string_analyzer.analyze(pe_analyzer.raw_data)

    if verbose:
        print(f"\nStrings Found: {string_analysis.total_strings}")
        print(f"  ASCII: {string_analysis.ascii_count}")
        print(f"  Unicode: {string_analysis.unicode_count}")

        if string_analysis.urls:
            print(f"\n  URLs: {len(string_analysis.urls)}")
            for url in string_analysis.urls[:5]:
                print(f"    • {url[:80]}")
            if len(string_analysis.urls) > 5:
                print(f"    ... and {len(string_analysis.urls) - 5} more")

        if string_analysis.ip_addresses:
            print(f"\n  IP Addresses: {len(string_analysis.ip_addresses)}")
            for ip in string_analysis.ip_addresses[:5]:
                print(f"    • {ip}")

        if string_analysis.suspicious_strings:
            print(
                f"\n⚠️  Suspicious Patterns: {len(string_analysis.suspicious_strings)}"
            )
            for match in string_analysis.suspicious_strings[:10]:
                print(f"    • [{match.pattern_type}] {match.context}")

        if string_analysis.warnings:
            print(f"\n  Warnings:")
            for warning in string_analysis.warnings:
                print(f"    {warning}")

    # ========================================
    # PHASE 3: YARA Scanning
    # ========================================
    if verbose:
        print("\n" + "=" * 70)
        print("PHASE 3: YARA SCANNING")
        print("=" * 70)

    yara_result = None
    if config.yara.enabled:
        yara_scanner = YaraScanner(config)
        yara_result = yara_scanner.scan(filepath)

        if verbose:
            if not yara_result.available:
                print("\n⚠️  YARA not available. Install with: pip install yara-python")
            elif not yara_result.scanned:
                print(f"\n⚠️  YARA scan skipped: {yara_result.warnings}")
            else:
                print(f"\nYARA Matches: {len(yara_result.matches)}")
                if yara_result.matches:
                    for match in yara_result.matches:
                        print(
                            f"  • {match.rule} [{match.namespace}] (Score: {match.score})"
                        )
                    print(f"\n  Total YARA Score: {yara_result.total_score}")

                for warning in yara_result.warnings:
                    print(f"  {warning}")
    else:
        if verbose:
            print("\n  YARA scanning disabled in config")

    # ========================================
    # PHASE 4: Behavioral Analysis
    # ========================================
    if verbose:
        print("\n" + "=" * 70)
        print("PHASE 4: BEHAVIORAL ANALYSIS")
        print("=" * 70)

    # Extract features
    extractor = FeatureExtractor(filepath, config)
    features = extractor.extract_all()

    iat = features["iat_analysis"]
    ui = features["ui_indicators"]
    trust = features["trust_signals"]
    exports = features["export_analysis"]

    if verbose:
        print(f"\nImport Analysis:")
        print(f"  Total Imports: {iat['total_imports']}")
        print(f"  DLLs: {iat['dll_count']}")
        print(
            f"  Ordinal Imports: {iat['ordinal_count']} ({iat['ordinal_ratio']*100:.1f}%)"
        )
        if iat["has_critical_loaders"]:
            print(f"  ⚠️  Manual Loaders: {len(iat['critical_loaders'])}")
        if iat["is_minimal"]:
            print(f"  ⚠️  Minimal imports (possible manual resolution)")

        print(f"\nUI Indicators:")
        print(f"  Subsystem: {ui['subsystem_name']}")
        print(f"  Has UI DLLs: {'Yes' if ui['has_ui_dlls'] else 'No'}")
        print(f"  Has Network DLLs: {'Yes' if ui['has_network_dlls'] else 'No'}")
        if ui["is_headless"]:
            print(f"  ⚠️  HEADLESS: Network without UI")

        print(f"\nTrust Signals:")
        print(f"  Trust Level: {trust['trust_level']}")
        print(f"  Digital Signature: {'Yes ✅' if trust['has_signature'] else 'No ❌'}")
        print(f"  Version Info: {'Yes' if trust['has_version_info'] else 'No'}")
        print(f"  Manifest: {'Yes' if trust['has_manifest'] else 'No'}")
        print(f"  Has Resources: {'Yes' if trust['has_resources'] else 'No'}")
        if trust["trust_reasons"]:
            for reason in trust["trust_reasons"]:
                print(f"    • {reason}")

        if exports["has_exports"]:
            print(f"\nExport Analysis:")
            print(f"  Exports: {exports['export_count']}")
            if exports["forwarder_count"] > 0:
                print(f"  Forwarders: {exports['forwarder_count']}")
            if exports["is_suspicious"]:
                print(f"  ⚠️  Suspicious export patterns detected")
                for reason in exports["suspicion_reasons"]:
                    print(f"    • {reason}")

    # Correlate features with section analysis
    correlation_engine = CorrelationEngine(config)
    correlation = correlation_engine.correlate(features, section_analyses)

    if verbose and correlation["capabilities"]:
        print(f"\n⚠️  Detected Capabilities:")
        for cap in correlation["capabilities"]:
            obf_note = (
                f" (×{cap['obfuscation_multiplier']:.1f})"
                if cap["is_obfuscated"]
                else ""
            )
            conf_note = f" [{cap['confidence']*100:.0f}%]"
            print(
                f"  • {cap['description']}: {cap['final_score']} pts{obf_note}{conf_note}"
            )
            print(f"    APIs: {', '.join(cap['matched_apis'][:5])}")

    # ========================================
    # PHASE 5: Final Verdict
    # ========================================
    if verbose:
        print("\n" + "=" * 70)
        print("PHASE 5: FINAL VERDICT")
        print("=" * 70)

    verdict_engine = VerdictEngine(config)
    verdict = verdict_engine.generate_verdict(
        features, correlation, structural_score, string_analysis
    )

    # Add YARA score to final assessment
    if yara_result and yara_result.total_score > 0:
        # Incorporate YARA findings
        yara_boost = min(20, yara_result.total_score // 5)
        verdict["final_score"] = min(100, verdict["final_score"] + yara_boost)

        # Update threat level if needed
        if verdict["final_score"] >= config.scoring.critical_threshold:
            verdict["threat_level"] = "CRITICAL"
        elif verdict["final_score"] >= config.scoring.high_threshold:
            verdict["threat_level"] = "HIGH"

    if verbose:
        print(f"\nScore Breakdown:")
        print(
            f"  Structural:  {structural_score}/100 (contributes {min(40, int(structural_score * 0.5))} pts)"
        )
        print(f"  Behavioral:  {correlation['total_capability_score']}/80")
        print(f"  Strings:     {verdict['string_score']}/100")
        if yara_result:
            print(f"  YARA:        {yara_result.total_score}/100")
        print(f"  {'─'*40}")
        print(f"  Final Score: {verdict['final_score']}/100")

        if verdict.get("trust_multiplier", 1.0) < 1.0:
            print(
                f"\n  Trust reduction applied: {(1-verdict['trust_multiplier'])*100:.0f}%"
            )

        print(f"\n  Threat Level: {verdict['threat_level']}")
        print(f"  Primary Driver: {verdict['primary_driver']}")

        print(f"\n  Attribution:")
        for category, score in verdict["attribution"].items():
            bar = "█" * (score // 5)
            print(f"    {category:<12}: {score:>3} {bar}")

    # ========================================
    # Generate Report
    # ========================================
    report = ReportGenerator.generate(
        filepath=filepath,
        verdict=verdict,
        features=features,
        section_analyses=section_analyses,
        string_analysis=string_analysis,
        yara_result=yara_result,
    )

    # Print final summary
    if verbose:
        print(f"\n{'='*70}")
        threat_emojis = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "CLEAN": "✅",
        }
        emoji = threat_emojis.get(verdict["threat_level"], "❓")
        print(
            f"{emoji} {verdict['threat_level']} THREAT - Score: {verdict['final_score']}/100"
        )
        print(f"{'='*70}")

        print("\nRecommendations:")
        for rec in verdict.get("recommendations", []):
            print(f"  {rec}")

        if verdict["reasons"]:
            print("\nDetailed Findings:")
            for reason in verdict["reasons"]:
                print(f"  {reason}")

    # Save report if requested
    if output_path:
        output_path = Path(output_path)

        if output_format == "json" or output_path.suffix == ".json":
            report.save_json(str(output_path))
        elif output_format == "md" or output_path.suffix == ".md":
            with open(output_path, "w") as f:
                f.write(report.to_markdown())
        elif output_format == "html" or output_path.suffix == ".html":
            with open(output_path, "w") as f:
                f.write(report.to_html())
        elif output_format == "sarif" or output_path.suffix == ".sarif":
            import json

            with open(output_path, "w") as f:
                json.dump(report.to_sarif(), f, indent=2)
        else:
            report.save_json(str(output_path))

        if verbose:
            print(f"\n✓ Report saved to: {output_path}")

    return report


def main():
    parser = argparse.ArgumentParser(
        description="PE-Sentinel - Static Malware Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyze.py malware.exe
  python analyze.py malware.exe -o report.json
  python analyze.py malware.exe -o report.html --format html
  python analyze.py malware.exe --config custom_config.json
  python analyze.py --create-yara-rules
        """,
    )

    parser.add_argument("file", nargs="?", help="PE file to analyze")
    parser.add_argument("-o", "--output", help="Output report path")
    parser.add_argument(
        "-f",
        "--format",
        choices=["json", "md", "html", "sarif"],
        help="Output format (default: json)",
    )
    parser.add_argument("-c", "--config", help="Path to config file")
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Quiet mode (minimal output)"
    )
    parser.add_argument(
        "--create-yara-rules",
        action="store_true",
        help="Create sample YARA rules in ./rules/",
    )
    parser.add_argument("--save-config", help="Save default config to file")

    args = parser.parse_args()

    # Handle special commands
    if args.create_yara_rules:
        rules_file = create_sample_rules()
        print(f"✓ Created sample YARA rules: {rules_file}")
        return

    if args.save_config:
        config = AnalysisConfig()
        config.save(args.save_config)
        print(f"✓ Saved default config to: {args.save_config}")
        return

    # Print banner
    if not args.quiet:
        print_banner()

    # Get file to analyze
    filepath = args.file
    if not filepath:
        if GUI_AVAILABLE:
            print("Please select a PE file to analyze...")
            filepath = select_file_gui()

        if not filepath:
            print("Usage: python analyze.py <file.exe>")
            print("       python analyze.py (opens file picker)")
            sys.exit(1)

    if not Path(filepath).exists():
        print(f"Error: File '{filepath}' not found")
        sys.exit(1)

    # Load config
    config = get_config(args.config) if args.config else AnalysisConfig()

    # Run analysis
    try:
        report = analyze_file(
            filepath=filepath,
            config=config,
            verbose=not args.quiet,
            output_format=args.format,
            output_path=args.output,
        )

        # Return exit code based on threat level
        exit_codes = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
            "CLEAN": 0,
        }
        sys.exit(exit_codes.get(report.threat_level, 0))

    except Exception as e:
        print(f"\n❌ Error during analysis: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
