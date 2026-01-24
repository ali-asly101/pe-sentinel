# test_disasm.py
import code
import sys
from capstone import *
import pefile
import math
import tkinter as tk
from tkinter import filedialog


def calculate_entropy(data):
    """Returns Shannon Entropy of data (0.0 to 8.0)"""
    if not data:
        return 0.0
    entropy = 0
    # Create frequency list for all 256 possible byte values
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log(p_x, 2)
    return entropy


def get_file_entropy(path):
    with open(path, "rb") as f:
        data = f.read()
    return calculate_entropy(data)


def check_for_upx(pe):
    """Detect if the file is packed with UPX"""
    for section in pe.sections:
        name = section.Name.decode().rstrip("\x00")
        if "UPX" in name:
            return True
    return False


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

is_upx = check_for_upx(pe)
if is_upx:
    print("!!! WARNING: UPX Packer Detected !!!")
    print("Static disassembly and string search will be inaccurate.")


def check_stealth_packing(pe):
    print("\n--- Stealth Analysis ---")
    for section in pe.sections:
        # Check for the Virtual vs Raw Size Gap
        # If VirtualSize is much bigger than RawSize, it's a 'loading' area
        if section.Misc_VirtualSize > (section.SizeOfRawData * 3):
            name = section.Name.decode().rstrip("\x00")
            print(f"[!] Warning: Section {name} expands significantly in RAM.")
            print(f"    Possible 'Code Unfolding' detected.")

    # Check for weird alignment
    if pe.OPTIONAL_HEADER.SectionAlignment < 0x1000:
        print(
            f"[!] Warning: Non-standard Section Alignment: {hex(pe.OPTIONAL_HEADER.SectionAlignment)}"
        )


def get_section_permissions(characteristics):
    perms = ""
    if characteristics & 0x40000000:
        perms += "R"
    if characteristics & 0x80000000:
        perms += "W"
    if characteristics & 0x20000000:
        perms += "X"
    return perms


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
        if instruction.mnemonic == "":
            print(f"Dead/Invalid code found at {hex(instruction.address)}")

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
    global_entropy = get_file_entropy(file_path)  # Calculate for the whole file

    entry_disasm = disasm_n_instructions(pe, entry_rva, count=200)
    text_disasm = disasm_code_section(pe)
    if check_signature_directory():
        print("File is signed.")
    check_stealth_packing(pe)
    return {
        "global_entropy": global_entropy,
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


def classify_entropy(entropy, section_name):
    """Classify section based on entropy with context"""

    # Adjust thresholds based on section type
    if section_name == ".text":
        if entropy > 6.8:
            return "High Entropy (Possible Obfuscation/Packing)"
        elif entropy < 4.0:
            return "Low Entropy (Sparse Code/Debugging)"
        else:
            return "Normal Code"

    elif section_name in [".data", ".rdata"]:
        if entropy > 7.5:
            return "ENCRYPTED/COMPRESSED DATA"
        elif entropy < 2.0:
            return "Mostly Zeros/Padding"
        else:
            return "Normal Data"

    elif section_name == ".rsrc":
        # Resources naturally have high entropy (images, etc.)
        if entropy > 7.8:
            return "High (May Contain Compressed Resources)"
        else:
            return "Normal Resources"

    else:
        if entropy > 7.2:
            return "PACKED/ENCRYPTED"
        elif entropy < 1.0:
            return "EMPTY/PADDING"
        else:
            return "Normal"


def show_sections():
    """Display sections with detailed analysis"""
    print(
        f"\n{'Section':<12} {'VirtAddr':<12} {'VirtSize':<12} {'RawSize':<12} {'Perms':<6} {'Entropy':<8} {'Status'}"
    )
    print("-" * 100)

    for section in pe.sections:
        perms = get_section_permissions(section.Characteristics)
        name = section.Name.decode().rstrip("\x00")
        data = section.get_data()
        entropy = calculate_entropy(data)

        # Classify based on multiple factors
        status = classify_entropy(entropy, name)

        # Override with more specific warnings
        if "W" in perms and "X" in perms:
            status = "⚠️  W+X (SELF-MODIFYING CODE)"

        print(
            f"{name:<12} {hex(section.VirtualAddress):<12} "
            f"{section.Misc_VirtualSize:<12} {section.SizeOfRawData:<12} "
            f"{perms:<6} {entropy:<8.2f} {status}"
        )


def check_signature_directory():
    """Check if the file has a security directory (signature)"""
    # Look for the Security Directory index (Entry 4)
    security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    ]

    if security_dir.VirtualAddress > 0 and security_dir.Size > 0:
        print(f"[+] File has a Digital Signature (Size: {security_dir.Size} bytes)")
        return True
    else:
        print("[!] WARNING: File is UNSIGNED (No security directory found)")
        return False


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
