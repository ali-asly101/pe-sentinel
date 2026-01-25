#!/usr/bin/env python3
"""
Full PE Analysis Tool
Combines interactive CLI (cli.py) with Sentinel behavioral analysis (analyze.py)
Provides the most comprehensive threat assessment
"""

import sys
import tkinter as tk
from tkinter import filedialog
from pathlib import Path

from core.pe_parser import PEAnalyzer
from core.disassembler import Disassembler
from core.analyzers import SectionAnalyzer, PackerDetector, StringExtractor
from core.threat_scorer import ThreatScorer
from core.sentinel.extractors import FeatureExtractor
from core.sentinel.correlators import CorrelationEngine
from core.sentinel.verdict_engine import VerdictEngine


def select_file() -> str:
    """Open file dialog to select PE file"""
    root = tk.Tk()
    root.withdraw()

    filepath = filedialog.askopenfilename(
        title="Select a PE file to analyze",
        filetypes=[("Executable Files", "*.exe *.dll *.sys"), ("All Files", "*.*")],
    )

    if not filepath:
        print("No file selected. Exiting.")
        sys.exit(1)

    return filepath


def main():
    # Check if file was passed as argument or use file picker
    if len(sys.argv) >= 2:
        filepath = sys.argv[1]
    else:
        print("Please select a PE file to analyze...")
        filepath = select_file()

    if not Path(filepath).exists():
        print(f"Error: File '{filepath}' not found")
        sys.exit(1)

    print(f"\n{'='*70}")
    print(f"FULL PE ANALYSIS: {Path(filepath).name}")
    print(f"{'='*70}\n")

    try:
        # ========================================
        # PHASE 1: Core Analysis (from cli.py)
        # ========================================
        print("=" * 70)
        print("PHASE 1: STRUCTURAL ANALYSIS")
        print("=" * 70)

        pe_analyzer = PEAnalyzer(filepath)
        sections = pe_analyzer.get_sections()
        imports = pe_analyzer.get_imports()
        packers = PackerDetector.detect_known_packers(sections)

        # Section-level analysis
        section_analyses = []
        suspicious_sections = []

        print("\nSection Analysis:")
        print(f"{'Section':<12} {'Entropy':<8} {'Ratio':<8} {'Score':<6} {'Level':<10}")
        print("-" * 60)

        for section in sections:
            analysis = SectionAnalyzer.analyze_section(section)
            section_analyses.append(analysis)

            if analysis.is_suspicious:
                suspicious_sections.append(analysis)

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
                f"{analysis.suspicion_score:<6} "
                f"{emoji} {analysis.suspicion_level}"
            )

        section_max_score = max(a.suspicion_score for a in section_analyses)

        # Show detailed warnings for suspicious sections
        if suspicious_sections:
            print(f"\n⚠️  Suspicious Sections Detected:")
            for analysis in suspicious_sections:
                print(f"\n  {analysis.name} ({analysis.suspicion_score}/100):")
                for warning in analysis.warnings:
                    print(f"    • {warning}")

        # Threat scoring (original simple method)
        scorer = ThreatScorer(sections, imports, pe_analyzer.is_signed(), packers)
        simple_threat_score, simple_threat_reasons = scorer.calculate_score()

        print(f"\nSimple Threat Score: {simple_threat_score}/100")

        # ========================================
        # PHASE 2: Behavioral Analysis (Sentinel)
        # ========================================
        print("\n" + "=" * 70)
        print("PHASE 2: BEHAVIORAL ANALYSIS (PE-Sentinel)")
        print("=" * 70)

        # Extract behavioral features
        extractor = FeatureExtractor(filepath)
        features = extractor.extract_all()

        # Display key behavioral features
        iat = features["iat_analysis"]
        ui = features["ui_indicators"]
        trust = features["trust_signals"]

        print(f"\nImport Analysis:")
        print(f"  Total Imports: {iat['total_imports']}")
        print(f"  DLLs: {iat['dll_count']}")
        print(
            f"  Ordinal Imports: {iat['ordinal_count']} ({iat['ordinal_ratio']*100:.1f}%)"
        )
        if iat["critical_loaders"]:
            print(f"  ⚠️  Manual Loaders: {len(iat['critical_loaders'])}")

        print(f"\nUI Indicators:")
        print(f"  Has UI DLLs: {'Yes' if ui['has_ui_dlls'] else 'No'}")
        print(f"  Has Network DLLs: {'Yes' if ui['has_network_dlls'] else 'No'}")
        if ui["is_headless"]:
            print(f"  ⚠️  HEADLESS: Network without UI")

        print(f"\nTrust Signals:")
        print(f"  Digital Signature: {'Yes' if trust['has_signature'] else 'No'}")
        print(f"  Version Info: {'Yes' if trust['has_version_info'] else 'No'}")
        print(f"  Has Resources: {'Yes' if trust['has_resources'] else 'No'}")

        # Correlate with section analysis
        correlation = CorrelationEngine.correlate(features, section_analyses)

        # Show detected capabilities
        if correlation["capabilities"]:
            print(f"\n⚠️  Detected Capabilities:")
            for cap in correlation["capabilities"]:
                obf_note = (
                    f" (×{cap['obfuscation_multiplier']:.1f})"
                    if cap["is_obfuscated"]
                    else ""
                )
                print(f"  • {cap['description']}: {cap['final_score']} pts{obf_note}")
                print(f"    Matched APIs: {', '.join(cap['matched_apis'][:5])}")

        # Generate verdict
        verdict = VerdictEngine.generate_verdict(features, correlation)

        print(
            f"\nBehavioral Threat Score: {verdict['final_score']}/100 ({verdict['threat_level']})"
        )

        # ========================================
        # PHASE 3: Combined Assessment
        # ========================================
        print("\n" + "=" * 70)
        print("PHASE 3: COMBINED THREAT ASSESSMENT")
        print("=" * 70)

        # Calculate overall score (weighted)
        structural_score = section_max_score
        behavioral_score = verdict["final_score"]

        # Use max score (worst case)
        overall_score = max(structural_score, behavioral_score)

        print(f"\nScore Breakdown:")
        print(f"  Structural Analysis:  {structural_score}/100")
        print(f"  Simple Threat Score:  {simple_threat_score}/100")
        print(f"  Behavioral Analysis:  {behavioral_score}/100")
        print(f"  {'─'*40}")
        print(f"  Overall Assessment:   {overall_score}/100")

        # Final verdict
        print(f"\n{'='*70}")
        if overall_score >= 80:
            print("🔴 CRITICAL THREAT")
            print("\nRecommendation:")
            print("  • IMMEDIATE ISOLATION required")
            print("  • Analyze in controlled sandbox environment")
            print("  • Report to security team")
            threat_emoji = "🔴"
        elif overall_score >= 60:
            print("🟠 HIGH THREAT")
            print("\nRecommendation:")
            print("  • DO NOT EXECUTE on production systems")
            print("  • Perform sandbox analysis")
            print("  • Review with security team")
            threat_emoji = "🟠"
        elif overall_score >= 40:
            print("🟡 MEDIUM THREAT")
            print("\nRecommendation:")
            print("  • Exercise caution before execution")
            print("  • Review manually")
            print("  • Monitor if executed")
            threat_emoji = "🟡"
        elif overall_score >= 20:
            print("🟢 LOW THREAT")
            print("\nRecommendation:")
            print("  • Appears relatively safe")
            print("  • Standard precautions apply")
            threat_emoji = "🟢"
        else:
            print("✅ CLEAN")
            print("\nRecommendation:")
            print("  • File appears legitimate")
            print("  • No significant threats detected")
            threat_emoji = "✅"

        # Key findings summary
        print(f"\n{'='*70}")
        print("KEY FINDINGS")
        print(f"{'='*70}")

        findings = []

        # Structural findings
        if suspicious_sections:
            findings.append(
                f"{threat_emoji} {len(suspicious_sections)} suspicious section(s) detected"
            )

        if packers:
            findings.append(f"{threat_emoji} Packer detected: {', '.join(packers)}")

        # Behavioral findings
        if correlation["capabilities"]:
            findings.append(
                f"{threat_emoji} {len(correlation['capabilities'])} malicious capability pattern(s)"
            )

        if ui["is_headless"]:
            findings.append(f"{threat_emoji} Headless network access (suspicious)")

        if not trust["has_signature"]:
            findings.append(f"⚠️  Unsigned binary")

        if iat["ordinal_ratio"] > 0.3:
            findings.append(
                f"{threat_emoji} High ordinal import ratio (hiding functions)"
            )

        if findings:
            for finding in findings:
                print(f"  • {finding}")
        else:
            print("  ✅ No significant threats detected")

        # Detailed breakdown
        print(f"\n{'='*70}")
        print("DETAILED ANALYSIS")
        print(f"{'='*70}")

        print("\nStructural Indicators:")
        if structural_score > 0:
            for analysis in section_analyses:
                if analysis.warnings:
                    print(f"  {analysis.name}:")
                    for warning in analysis.warnings:
                        print(f"    • {warning}")
        else:
            print("  ✅ No structural anomalies")

        print("\nBehavioral Indicators:")
        if verdict["reasons"]:
            for reason in verdict["reasons"]:
                print(f"  {reason}")
        else:
            print("  ✅ No behavioral anomalies")

        print(f"\n{'='*70}\n")

        # Save to file option
        save_report = input("Save detailed report to file? (y/n): ").lower().strip()
        if save_report == "y":
            report_path = Path(filepath).with_suffix(".analysis.txt")
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(f"PE Analysis Report\n")
                f.write(f"{'='*70}\n")
                f.write(f"File: {filepath}\n")
                f.write(f"Overall Threat: {overall_score}/100\n")
                f.write(f"\nStructural Score: {structural_score}/100\n")
                f.write(f"Behavioral Score: {behavioral_score}/100\n")
                f.write(f"\nKey Findings:\n")
                for finding in findings:
                    f.write(f"  {finding}\n")
            print(f"✓ Report saved to: {report_path}")

    except Exception as e:
        print(f"\n❌ Error during analysis: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
