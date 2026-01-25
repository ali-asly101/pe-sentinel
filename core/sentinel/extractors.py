"""
Phase 1: Feature Extraction
Extracts ONLY features NOT already in analyzers.py
- IAT analysis
- Trust signals
- UI indicators

Reuses existing section analysis from analyzers.py (no duplication)
"""

from typing import Dict, List
import pefile
import os


class FeatureExtractor:
    """Extract behavioral features for threat correlation"""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.pe = pefile.PE(filepath)

    def extract_all(self) -> Dict:
        """
        Extract all behavioral features.

        Note: Does NOT extract structural metrics (entropy, size ratio)
              Those come from analyzers.py to avoid duplication.
        """
        return {
            "iat_analysis": self.extract_iat_analysis(),
            "trust_signals": self.extract_trust_signals(),
            "ui_indicators": self.extract_ui_indicators(),
            "filename": os.path.basename(self.filepath),
        }

    # ============================================================
    # IAT Analysis
    # ============================================================

    def extract_iat_analysis(self) -> Dict:
        """
        Extract Import Address Table details.
        Goal: Understand WHAT the binary CAN do (capabilities).
        """
        if not hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            return {
                "has_imports": False,
                "total_imports": 0,
                "imports_by_dll": {},
                "ordinal_imports": [],
                "ordinal_count": 0,
                "ordinal_ratio": 0.0,
                "critical_loaders": [],
                "dll_count": 0,
                "all_functions": set(),
            }

        imports_by_dll = {}
        ordinal_count = 0
        ordinal_imports = []
        critical_loaders = []
        total_imports = 0
        all_functions = set()

        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8").lower()
            functions = []

            for imp in entry.imports:
                total_imports += 1

                if imp.name:
                    func_name = imp.name.decode("utf-8")
                else:
                    # Import by ordinal (hiding function name)
                    func_name = f"Ordinal_{imp.ordinal}"
                    ordinal_count += 1
                    ordinal_imports.append(
                        {
                            "dll": dll_name,
                            "ordinal": imp.ordinal,
                            "address": hex(imp.address) if imp.address else None,
                        }
                    )

                functions.append(
                    {
                        "name": func_name,
                        "address": hex(imp.address) if imp.address else None,
                        "is_ordinal": not bool(imp.name),
                    }
                )

                all_functions.add(func_name)

                # Track critical loader functions
                if func_name in [
                    "GetProcAddress",
                    "LoadLibraryA",
                    "LoadLibraryW",
                    "LoadLibraryExA",
                ]:
                    critical_loaders.append(
                        {
                            "dll": dll_name,
                            "function": func_name,
                        }
                    )

            imports_by_dll[dll_name] = functions

        return {
            "has_imports": True,
            "total_imports": total_imports,
            "imports_by_dll": imports_by_dll,
            "ordinal_count": ordinal_count,
            "ordinal_ratio": (
                ordinal_count / total_imports if total_imports > 0 else 0.0
            ),
            "ordinal_imports": ordinal_imports,
            "critical_loaders": critical_loaders,
            "dll_count": len(imports_by_dll),
            "all_functions": all_functions,
        }

    # ============================================================
    # Trust Signals
    # ============================================================

    def extract_trust_signals(self) -> Dict:
        """
        Extract indicators of legitimacy.
        Goal: Find reasons to TRUST this binary.
        """
        # Digital signature
        has_signature = False

        security_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        has_signature = security_dir.VirtualAddress > 0 and security_dir.Size > 0

        # Version info / Manifest / Resources
        has_version_info = False
        has_manifest = False
        has_resources = False

        if hasattr(self.pe, "DIRECTORY_ENTRY_RESOURCE"):
            has_resources = True

            for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource_type.name is not None:
                    type_name = str(resource_type.name)
                else:
                    type_name = pefile.RESOURCE_TYPE.get(
                        resource_type.struct.Id, "UNKNOWN"
                    )

                if type_name == "RT_VERSION":
                    has_version_info = True
                elif type_name == "RT_MANIFEST":
                    has_manifest = True

        # File size
        file_size = os.path.getsize(self.filepath)
        is_suspiciously_small = file_size < 10 * 1024  # < 10 KB

        return {
            "has_signature": has_signature,
            "has_version_info": has_version_info,
            "has_manifest": has_manifest,
            "has_resources": has_resources,
            "file_size": file_size,
            "is_suspiciously_small": is_suspiciously_small,
            "has_bulk": has_version_info or has_manifest or has_resources,
        }

    # ============================================================
    # UI Indicators
    # ============================================================

    def extract_ui_indicators(self) -> Dict:
        """
        Detect if this is a GUI application.
        Goal: Distinguish headless malware from legitimate GUI apps.
        """
        ui_dlls = {
            "user32.dll",
            "gdi32.dll",
            "comctl32.dll",
            "shell32.dll",
            "comdlg32.dll",
            "ole32.dll",
        }

        network_dlls = {
            "ws2_32.dll",
            "wininet.dll",
            "winhttp.dll",
            "wsock32.dll",
            "mswsock.dll",
            "urlmon.dll",
        }

        iat = self.extract_iat_analysis()
        imported_dlls = set(iat["imports_by_dll"].keys())

        has_ui_dlls = bool(ui_dlls & imported_dlls)
        has_network_dlls = bool(network_dlls & imported_dlls)

        # Check subsystem
        is_gui_subsystem = (
            self.pe.OPTIONAL_HEADER.Subsystem == 2
        )  # IMAGE_SUBSYSTEM_WINDOWS_GUI
        is_console_subsystem = (
            self.pe.OPTIONAL_HEADER.Subsystem == 3
        )  # IMAGE_SUBSYSTEM_WINDOWS_CUI

        return {
            "has_ui_dlls": has_ui_dlls,
            "has_network_dlls": has_network_dlls,
            "is_gui_subsystem": is_gui_subsystem,
            "is_console_subsystem": is_console_subsystem,
            "is_headless": has_network_dlls and not has_ui_dlls,  # Network but no UI
            "imported_dlls": imported_dlls,
        }
