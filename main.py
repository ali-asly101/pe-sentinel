# test_disasm.py
import code
import sys
from capstone import *
import pefile
import tkinter as tk
from tkinter import filedialog

# Open file dialog
root = tk.Tk()
root.withdraw()
file_path = filedialog.askopenfilename(
    title="Select a Windows executable",
    filetypes=[("Executable Files", "*.exe *.dll"), ("All Files", "*.*")],
)

if not file_path:
    print("No file selected. Exiting.")
    sys.exit(1)

# Load PE file with error handling
try:
    pe = pefile.PE(file_path)
    print(f"Loaded: {file_path}")
except pefile.PEFormatError as e:
    print(f"Error: Not a valid PE file - {e}")
    sys.exit(1)
except Exception as e:
    print(f"Error loading file: {e}")
    sys.exit(1)


def get_architecture(pe):
    """Detect PE architecture"""
    machine = pe.FILE_HEADER.Machine
    if machine == 0x14C:
        return CS_ARCH_X86, CS_MODE_32
    elif machine == 0x8664:
        return CS_ARCH_X86, CS_MODE_64
    else:
        raise ValueError(f"Unsupported architecture: {hex(machine)}")


def disasm_n_instructions(pe, rva, count=100):
    """Disassemble N instructions from given RVA"""
    arch, mode = get_architecture(pe)
    offset = pe.get_offset_from_rva(rva)
    code = pe.__data__[offset : offset + count * 15]  # Max 15 bytes per instruction

    md = Cs(arch, mode)
    instructions = []

    for instruction in md.disasm(code, pe.OPTIONAL_HEADER.ImageBase + rva):
        instructions.append(
            f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}"
        )
        if len(instructions) >= count:
            break

    return instructions


def disasm_code_section(pe):
    """Disassemble entire .text section"""
    arch, mode = get_architecture(pe)

    # Find .text section
    text_section = None
    for section in pe.sections:
        if section.Name.startswith(b".text"):
            text_section = section
            break

    if not text_section:
        print("Warning: No .text section found!")
        return []

    code = text_section.get_data()
    base_addr = pe.OPTIONAL_HEADER.ImageBase + text_section.VirtualAddress

    print(f"Disassembling .text section ({len(code)} bytes)...")

    md = Cs(arch, mode)
    instructions = []

    for i, instruction in enumerate(md.disasm(code, base_addr)):
        instructions.append(
            f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}"
        )
        if (i + 1) % 10000 == 0:
            print(f"  {i + 1} instructions...")

    print(f"Complete! {len(instructions)} total instructions")
    return instructions


def analyze_binary():
    """Perform full binary analysis"""
    entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    entry_disasm = disasm_n_instructions(pe, entry_rva, count=200)
    text_disasm = disasm_code_section(pe)

    return {
        "entry_point": {
            "address": f"0x{entry_rva:x}",
            "instructions": entry_disasm,
        },
        "full_disassembly": {
            "instructions": text_disasm,
            "count": len(text_disasm),
        },
    }


# Helper functions
def show_entry(count=20):
    """Show first N instructions from entry point"""
    for inst in disasm_data["entry_point"]["instructions"][:count]:
        print(inst)


def search_inst(mnemonic):
    """Search for instructions by mnemonic"""
    results = [
        inst
        for inst in disasm_data["full_disassembly"]["instructions"]
        if mnemonic.lower() in inst.lower()
    ]
    print(f"Found {len(results)} matches for '{mnemonic}':")
    for inst in results[:50]:
        print(inst)
    return results


def find_strings():
    """Extract ASCII strings"""
    strings = []
    for section in pe.sections:
        if b".rdata" in section.Name or b".data" in section.Name:
            data = section.get_data()
            current = ""
            for byte in data:
                if 32 <= byte <= 126:
                    current += chr(byte)
                else:
                    if len(current) >= 4:
                        strings.append(current)
                    current = ""

    print(f"Found {len(strings)} strings:")
    for s in strings[:50]:
        print(f"  {s}")
    return strings


def show_imports():
    """Display imports"""
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(f"\n{entry.dll.decode('utf-8')}:")
            for imp in entry.imports[:20]:
                name = (
                    imp.name.decode("utf-8") if imp.name else f"Ordinal_{imp.ordinal}"
                )
                print(f"  {name}")
    else:
        print("No imports found")


def show_sections():
    """Display sections"""
    print(f"\n{'Section':<12} {'VirtAddr':<12} {'VirtSize':<12} {'RawSize':<12}")
    print("-" * 60)
    for section in pe.sections:
        name = section.Name.decode().rstrip("\x00")
        print(
            f"{name:<12} {hex(section.VirtualAddress):<12} "
            f"{section.Misc_VirtualSize:<12} {section.SizeOfRawData:<12}"
        )


# Run analysis
disasm_data = analyze_binary()

# Start console
banner = f"""
╔════════════════════════════════════════════════════════════════╗
║          Interactive PE Disassembly Console                    ║
╚════════════════════════════════════════════════════════════════╝

File: {file_path}
Entry Point: {disasm_data['entry_point']['address']}

Commands: show_entry(), search_inst(), find_strings(), show_imports(), show_sections()
"""

code.interact(
    banner=banner,
    local={
        "disasm_data": disasm_data,
        "pe": pe,
        "show_entry": show_entry,
        "search_inst": search_inst,
        "find_strings": find_strings,
        "show_imports": show_imports,
        "show_sections": show_sections,
    },
)
