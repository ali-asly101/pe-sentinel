"""
PE file parsing and metadata extraction
"""

import pefile
from typing import Dict, List, Optional


class PEAnalyzer:
    """Handles PE file parsing and basic metadata extraction"""

    def __init__(self, filepath: str):
        self.filepath = filepath
        # 1. We must read the raw bytes first for the String Analyzer and YARA
        with open(filepath, "rb") as f:
            self.raw_data = f.read()  # <--- Added this line

        # 2. Pass the data to pefile so it doesn't have to read the file again
        self.pe = pefile.PE(data=self.raw_data)
        self._cache = {}

    def get_architecture(self) -> tuple:
        """Returns (arch, mode) for Capstone"""
        from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64

        machine = self.pe.FILE_HEADER.Machine
        if machine == 0x14C:  # IMAGE_FILE_MACHINE_I386
            return CS_ARCH_X86, CS_MODE_32
        elif machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
            return CS_ARCH_X86, CS_MODE_64
        else:
            raise ValueError(f"Unsupported architecture: {hex(machine)}")

    def get_entry_point(self) -> Dict[str, any]:
        """Get entry point information"""
        entry_rva = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry_offset = self.pe.get_offset_from_rva(entry_rva)

        return {"rva": entry_rva, "offset": entry_offset, "address": f"0x{entry_rva:x}"}

    def get_sections(self) -> List[Dict]:
        """Get all PE sections with metadata"""
        sections = []

        for section in self.pe.sections:
            sections.append(
                {
                    "name": section.Name.decode().rstrip("\x00"),
                    "virtual_address": section.VirtualAddress,
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "characteristics": section.Characteristics,
                    "data": section.get_data(),
                    "permissions": self._get_permissions(section.Characteristics),
                }
            )

        return sections

    def get_text_section(self) -> Optional[Dict]:
        """Get .text section specifically"""
        for section_data in self.get_sections():
            if section_data["name"] == ".text":
                return section_data
        return None

    def get_imports(self) -> List[Dict]:
        """Extract imported DLLs and functions"""
        if not hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            return []

        imports = []
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8")
            functions = []

            for imp in entry.imports:
                func_name = (
                    imp.name.decode("utf-8", "ignore")
                    if imp.name
                    else f"Ordinal_{imp.ordinal}"
                )
                functions.append(
                    {
                        "name": func_name,
                        "address": hex(imp.address) if imp.address else None,
                    }
                )

            imports.append({"dll": dll_name, "functions": functions})

        return imports

    def is_signed(self) -> bool:
        """Check if PE has digital signature"""
        security_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        return security_dir.VirtualAddress > 0 and security_dir.Size > 0

    def get_metadata(self) -> Dict:
        """Get comprehensive PE metadata"""
        import os

        return {
            "filename": os.path.basename(self.filepath),
            "filesize": os.path.getsize(self.filepath),
            "architecture": "x64" if self.get_architecture()[1] == 64 else "x86",
            "entry_point": self.get_entry_point()["address"],
            "sections_count": len(self.pe.sections),
            "is_signed": self.is_signed(),
            "image_base": hex(self.pe.OPTIONAL_HEADER.ImageBase),
        }

    @staticmethod
    def _get_permissions(characteristics: int) -> str:
        """Convert section characteristics to RWX string"""
        perms = ""
        if characteristics & 0x40000000:
            perms += "R"
        if characteristics & 0x80000000:
            perms += "W"
        if characteristics & 0x20000000:
            perms += "X"
        return perms

    def close(self):
        """Clean up PE file handle"""
        self.pe.close()
