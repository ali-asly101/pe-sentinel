"""
Disassembly engine using Capstone
"""

from capstone import Cs
from typing import List, Dict
from .pe_parser import PEAnalyzer


class Disassembler:
    """Handles disassembly of PE sections"""

    def __init__(self, pe_analyzer: PEAnalyzer):
        self.pe_analyzer = pe_analyzer
        self.pe = pe_analyzer.pe
        arch, mode = pe_analyzer.get_architecture()
        self.md = Cs(arch, mode)

    def disasm_from_rva(self, rva: int, count: int = 200) -> List[Dict]:
        """Disassemble N instructions from given RVA"""
        offset = self.pe.get_offset_from_rva(rva)
        code = self.pe.__data__[offset : offset + count * 15]

        base_addr = self.pe.OPTIONAL_HEADER.ImageBase + rva
        instructions = []

        for inst in self.md.disasm(code, base_addr):
            instructions.append(
                {
                    "address": f"0x{inst.address:x}",
                    "mnemonic": inst.mnemonic,
                    "op_str": inst.op_str,
                    "bytes": inst.bytes.hex(),
                    "size": inst.size,
                }
            )

            if len(instructions) >= count:
                break

        return instructions

    def disasm_text_section(self, progress_callback=None) -> List[Dict]:
        """Disassemble entire .text section"""
        text_section = self.pe_analyzer.get_text_section()

        if not text_section:
            return []

        code = text_section["data"]
        base_addr = self.pe.OPTIONAL_HEADER.ImageBase + text_section["virtual_address"]

        instructions = []

        for i, inst in enumerate(self.md.disasm(code, base_addr)):
            instructions.append(
                {
                    "address": f"0x{inst.address:x}",
                    "mnemonic": inst.mnemonic,
                    "op_str": inst.op_str,
                    "bytes": inst.bytes.hex(),
                    "size": inst.size,
                }
            )

            # Progress callback every 10k instructions
            if progress_callback and (i + 1) % 10000 == 0:
                progress_callback(i + 1)

        return instructions

    def search_instruction(self, mnemonic: str, instructions: List[Dict]) -> List[Dict]:
        """Search for specific instruction mnemonic"""
        return [
            inst
            for inst in instructions
            if mnemonic.lower() in inst["mnemonic"].lower()
        ]
