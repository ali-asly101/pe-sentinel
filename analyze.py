#!/usr/bin/env python3
"""
Unified PE Analysis Tool
Combines section analysis (analyzers.py) with behavioral analysis (sentinel)
"""

import sys
import tkinter as tk
from tkinter import filedialog
from pathlib import Path

from core.pe_parser import PEAnalyzer
from core.analyzers import SectionAnalyzer
from core.sentinel.extractors import FeatureExtractor
from core.sentinel.correlators import CorrelationEngine
from core.sentinel.verdict_engine import VerdictEngine


def select_file() -> str:
    """Open file dialog to select PE file"""
    root = tk.Tk()
    root.withdraw()  # Hide the main window

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

    print(f"\nAnalyzing: {filepath}\n")

    try:
        # ========================================
        # Step 1: Parse PE & Analyze Sections
        # ========================================
        print("=" * 70)
        print("SECTION ANALYSIS (Structural)")
        print("=" * 70)

        pe_analyzer = PEAnalyzer(filepath)
        sections = pe_analyzer.get_sections()

        section_analyses = []
        for section in sections:
            analysis = SectionAnalyzer.analyze_section(section)
            section_analyses.append(analysis)

            print(
                f"\n{analysis.name}: {analysis.suspicion_score}/100 ({analysis.suspicion_level})"
            )
            if analysis.warnings:
                for warning in analysis.warnings:
                    print(f"  • {warning}")

        section_max_score = max(a.suspicion_score for a in section_analyses)

        # ========================================
        # Step 2: Behavioral Analysis (Sentinel)
        # ========================================
        print("\n" + "=" * 70)
        print("BEHAVIORAL ANALYSIS (PE-Sentinel)")
        print("=" * 70)

        # Extract behavioral features
        extractor = FeatureExtractor(filepath)
        features = extractor.extract_all()

        # Correlate with section analysis
        correlation = CorrelationEngine.correlate(features, section_analyses)

        # Generate verdict
        verdict = VerdictEngine.generate_verdict(features, correlation)

        print(
            f"\nThreat Score: {verdict['final_score']}/100 ({verdict['threat_level']})"
        )

        if verdict["is_likely_malicious"]:
            print("⚠️  LIKELY MALICIOUS\n")
        else:
            print("✓ Likely benign\n")

        print("Analysis Breakdown:")
        for reason in verdict["reasons"]:
            print(reason)

        # ========================================
        # Step 3: Combined Verdict
        # ========================================
        print("\n" + "=" * 70)
        print("FINAL VERDICT")
        print("=" * 70)

        overall = max(section_max_score, verdict["final_score"])

        print(f"\nStructural Analysis: {section_max_score}/100")
        print(f"Behavioral Analysis: {verdict['final_score']}/100")
        print(f"Overall Assessment:  {overall}/100")

        if overall >= 70:
            print("\n🔴 CRITICAL THREAT")
            print("   Recommendation: Isolate and analyze in sandbox")
        elif overall >= 50:
            print("\n🟠 HIGH THREAT")
            print("   Recommendation: Exercise extreme caution")
        elif overall >= 30:
            print("\n🟡 MEDIUM THREAT")
            print("   Recommendation: Review manually before execution")
        else:
            print("\n🟢 LOW THREAT")
            print("   Recommendation: Appears legitimate")

        print()

    except Exception as e:
        print(f"\n❌ Error during analysis: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
