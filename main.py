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
        """Show section analysis"""
        print(
            f"\n{'Section':<12} {'VirtAddr':<12} {'VSize':<10} {'RawSize':<10} {'Perms':<6} {'Entropy':<8} {'Status'}"
        )
        print("-" * 100)

        for section in sections:
            entropy = EntropyAnalyzer.calculate(section["data"])
            status = EntropyAnalyzer.classify(entropy, section["name"])

            if "W" in section["permissions"] and "X" in section["permissions"]:
                status = "⚠️  W+X (SELF-MODIFYING)"

            print(
                f"{section['name']:<12} "
                f"{hex(section['virtual_address']):<12} "
                f"{section['virtual_size']:<10} "
                f"{section['raw_size']:<10} "
                f"{section['permissions']:<6} "
                f"{entropy:<8.2f} "
                f"{status}"
            )

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
    banner = f"""
╔════════════════════════════════════════════════════════════════╗
║          Interactive PE Analysis Console                       ║
╚════════════════════════════════════════════════════════════════╝

File: {analysis_data['metadata']['filename']}
Threat: {analysis_data['threat_score']}/100 ({analysis_data['threat_level']})

Quick Start:
  show_summary()         - File overview
  show_threat_analysis() - Detailed threat assessment
  show_sections()        - Section analysis
  show_imports()         - Import table
  show_entry(50)         - First 50 instructions
  search_inst('call')    - Find CALL instructions
  find_strings()         - Extract strings
"""

    code.interact(
        banner=banner,
        local={
            "analysis_data": analysis_data,
            "pe_analyzer": pe_analyzer,
            "show_summary": show_summary,
            "show_threat_analysis": show_threat_analysis,
            "show_sections": show_sections,
            "show_entry": show_entry,
            "search_inst": search_inst,
            "find_strings": find_strings,
            "show_imports": show_imports,
        },
    )


if __name__ == "__main__":
    main()
