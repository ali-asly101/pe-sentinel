#!/usr/bin/env python3
"""
Interactive CLI for PE binary analysis
"""
import code
import sys
import tkinter as tk
from tkinter import filedialog

from core.pe_parser import PEAnalyzer
from core.disassembler import Disassembler
from core.analyzers import EntropyAnalyzer, PackerDetector, StringExtractor
from core.threat_scorer import ThreatScorer


def select_file() -> str:
    """Open file dialog to select PE file"""
    root = tk.Tk()
    root.withdraw()

    filepath = filedialog.askopenfilename(
        title="Select a Windows executable",
        filetypes=[("Executable Files", "*.exe *.dll"), ("All Files", "*.*")],
    )

    if not filepath:
        print("No file selected. Exiting.")
        sys.exit(1)

    return filepath


def main():
    # Select and load file
    filepath = select_file()

    try:
        pe_analyzer = PEAnalyzer(filepath)
        print(f"✓ Loaded: {filepath}")
    except Exception as e:
        print(f"✗ Error loading file: {e}")
        sys.exit(1)

    # Initialize components
    disasm = Disassembler(pe_analyzer)

    # Run initial analysis
    print("\n" + "=" * 70)
    print("ANALYZING...")
    print("=" * 70)

    sections = pe_analyzer.get_sections()
    imports = pe_analyzer.get_imports()
    packers = PackerDetector.detect_known_packers(sections)

    # Threat assessment
    scorer = ThreatScorer(sections, imports, pe_analyzer.is_signed(), packers)
    threat_score, threat_reasons = scorer.calculate_score()

    # Disassembly
    entry_point = pe_analyzer.get_entry_point()
    print(f"\nDisassembling from entry point {entry_point['address']}...")
    entry_disasm = disasm.disasm_from_rva(entry_point["rva"], count=200)

    print(f"Disassembling .text section...")
    text_disasm = disasm.disasm_text_section(
        progress_callback=lambda count: print(f"  {count} instructions...")
    )

    # Package results
    analysis_data = {
        "metadata": pe_analyzer.get_metadata(),
        "threat_score": threat_score,
        "threat_reasons": threat_reasons,
        "threat_level": scorer.get_threat_level(threat_score),
        "sections": sections,
        "imports": imports,
        "packers": packers,
        "entry_disasm": entry_disasm,
        "text_disasm": text_disasm,
    }

    # Helper functions for interactive console
    def show_summary():
        """Show file summary"""
        meta = analysis_data["metadata"]
        print("\n" + "=" * 70)
        print("FILE SUMMARY")
        print("=" * 70)
        print(f"File: {meta['filename']}")
        print(f"Size: {meta['filesize']:,} bytes")
        print(f"Architecture: {meta['architecture']}")
        print(f"Entry Point: {meta['entry_point']}")
        print(f"Signed: {'Yes' if meta['is_signed'] else 'No'}")
        print(
            f"\nThreat Score: {analysis_data['threat_score']}/100 ({analysis_data['threat_level']})"
        )
        print("=" * 70 + "\n")

    def show_threat_analysis():
        """Show detailed threat analysis"""
        print("\n" + "=" * 70)
        print("THREAT ANALYSIS")
        print("=" * 70)
        print(f"\nScore: {analysis_data['threat_score']}/100")
        print(f"Level: {analysis_data['threat_level']}\n")
        print("Indicators:")
        for reason in analysis_data["threat_reasons"]:
            print(f"  • {reason}")

        suspicious = scorer.get_suspicious_imports()
        if suspicious:
            print(f"\nSuspicious API Calls ({len(suspicious)}):")
            for api in suspicious[:20]:
                print(f"  • {api['dll']}!{api['function']} - {api['reason']}")

        print("=" * 70 + "\n")

    def show_sections():
        """Show enhanced section analysis"""
        from core.analyzers import SectionAnalyzer, SegmentEntropyAnalyzer

        print(
            f"\n{'Section':<12} {'Entropy':<8} {'Ratio':<8} {'Perms':<6} "
            f"{'Score':<6} {'Level':<10} {'Status'}"
        )
        print("-" * 100)

        for section in sections:
            analysis = SectionAnalyzer.analyze_section(section)

            # Emoji indicators
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
                f"{emoji} {analysis.suspicion_level:<10} "
                f"{analysis.entropy_status}"
            )

            # Show warnings
            if analysis.warnings:
                for w in analysis.warnings:
                    print(f"  └─ {w}")

        print()

    def show_section_details(section_name: str):
        """Show detailed analysis for a specific section"""
        from core.analyzers import SectionAnalyzer, SegmentEntropyAnalyzer

        # Find the section
        target_section = None
        for section in sections:
            if section["name"] == section_name:
                target_section = section
                break

        if not target_section:
            print(f"Section '{section_name}' not found")
            return

        # Analyze
        analysis = SectionAnalyzer.analyze_section(target_section)

        print(f"\n{'='*70}")
        print(f"Section: {analysis.name}")
        print(f"{'='*70}")
        print(f"Overall Entropy: {analysis.entropy:.2f} - {analysis.entropy_status}")
        print(f"Size Ratio: {analysis.size_ratio:.2f}x - {analysis.size_status}")
        print(f"Permissions: {analysis.permissions} - {analysis.permission_status}")
        print(
            f"Suspicion Score: {analysis.suspicion_score}/100 ({analysis.suspicion_level})"
        )

        # Segment analysis
        if analysis.segment_analysis["has_anomaly"]:
            print(f"\n⚠️ SEGMENT ANOMALY DETECTED:")
            print(f"  {analysis.segment_analysis['anomaly_reason']}")
            print(f"\nEntropy Distribution:")
            viz = SegmentEntropyAnalyzer.visualize_entropy_distribution(
                analysis.segment_analysis["entropies"],
                analysis.segment_analysis["chunk_size_kb"],
                section_name=analysis.name,  # ← Pass section name!
            )
            print(viz)
        else:
            print(f"\n✅ No segment anomalies detected")
            print(f"  Mean Entropy: {analysis.segment_analysis['mean']:.2f}")
            print(f"  Std Deviation: {analysis.segment_analysis['stddev']:.2f}")
            print(f"  Variance: {analysis.segment_analysis['variance']:.2f}")

        # Warnings
        if analysis.warnings:
            print(f"\nWarnings:")
            for w in analysis.warnings:
                print(f"  • {w}")

        print(f"{'='*70}\n")

    def find_suspicious_sections():
        """Find and list all suspicious sections"""
        from core.analyzers import SectionAnalyzer

        suspicious = []
        for section in sections:
            analysis = SectionAnalyzer.analyze_section(section)
            if analysis.is_suspicious:
                suspicious.append(analysis)

        if suspicious:
            print(f"\n⚠️ Found {len(suspicious)} suspicious section(s):\n")
            for analysis in suspicious:
                print(f"Section: {analysis.name}")
                print(
                    f"  Score: {analysis.suspicion_score}/100 ({analysis.suspicion_level})"
                )
                print(f"  Entropy: {analysis.entropy:.2f}")
                print(f"  Ratio: {analysis.size_ratio:.2f}x")

                if analysis.warnings:
                    print(f"  Warnings:")
                    for w in analysis.warnings:
                        print(f"    • {w}")
                print()
        else:
            print("✅ No suspicious sections found")

        return suspicious

    def show_entry(count=20):
        """Show first N instructions from entry point"""
        for inst in entry_disasm[:count]:
            print(f"{inst['address']}:\t{inst['mnemonic']}\t{inst['op_str']}")

    def search_inst(mnemonic):
        """Search for instruction mnemonic"""
        results = disasm.search_instruction(mnemonic, text_disasm)
        print(f"Found {len(results)} matches for '{mnemonic}':")
        for inst in results[:50]:
            print(f"{inst['address']}:\t{inst['mnemonic']}\t{inst['op_str']}")
        return results

    def find_strings():
        """Extract strings from data sections"""
        all_strings = []
        for section in sections:
            if section["name"] in [".rdata", ".data"]:
                strings = StringExtractor.extract_ascii(section["data"])
                all_strings.extend(strings)

        print(f"Found {len(all_strings)} strings:")
        for s in all_strings[:50]:
            print(f"  {s}")
        return all_strings

    def show_imports():
        """Show imports with suspicious API highlighting"""
        suspicious_apis = {api["function"] for api in scorer.get_suspicious_imports()}

        for dll in imports:
            print(f"\n{dll['dll']}:")
            for func in dll["functions"][:20]:
                if func["name"] in suspicious_apis:
                    print(f"  ⚠️  {func['name']}")
                else:
                    print(f"  {func['name']}")

    # Start interactive console
    # In main() function, update the banner:
    banner = f"""
    ╔════════════════════════════════════════════════════════════════╗
    ║          Interactive PE Analysis Console                       ║
    ╚════════════════════════════════════════════════════════════════╝

    File: {analysis_data['metadata']['filename']}
    Threat: {analysis_data['threat_score']}/100 ({analysis_data['threat_level']})

    Quick Start:
    show_summary()              - File overview
    show_threat_analysis()      - Detailed threat assessment
    show_sections()             - Section analysis with suspicion scores
    show_section_details(name)  - Deep dive into specific section
    find_suspicious_sections()  - List all suspicious sections
    show_imports()              - Import table
    show_entry(50)              - First 50 instructions
    search_inst('call')         - Find CALL instructions
    find_strings()              - Extract strings

    Examples:
    >>> show_sections()
    >>> show_section_details('.text')
    >>> find_suspicious_sections()
    """

    # Update the local dict:
    code.interact(
        banner=banner,
        local={
            "analysis_data": analysis_data,
            "pe_analyzer": pe_analyzer,
            "show_summary": show_summary,
            "show_threat_analysis": show_threat_analysis,
            "show_sections": show_sections,
            "show_section_details": show_section_details,  # NEW
            "find_suspicious_sections": find_suspicious_sections,  # NEW
            "show_entry": show_entry,
            "search_inst": search_inst,
            "find_strings": find_strings,
            "show_imports": show_imports,
        },
    )


if __name__ == "__main__":
    main()
