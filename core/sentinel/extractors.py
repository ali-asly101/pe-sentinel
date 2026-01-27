"""
Phase 1: Feature Extraction
- IAT analysis
- Trust signals (improved)
- UI indicators
- Export analysis (NEW)

Reuses existing section analysis from analyzers.py (no duplication)
"""

from typing import Dict, List, Set
import pefile
import os

from ..config import AnalysisConfig, DEFAULT_CONFIG


class FeatureExtractor:
    """Extract behavioral features for threat correlation"""

    def __init__(self, filepath: str, config: AnalysisConfig = None):
        self.filepath = filepath
        self.pe = pefile.PE(filepath)
        self.config = config or DEFAULT_CONFIG

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
            "export_analysis": self.extract_export_analysis(),
            "filename": os.path.basename(self.filepath),
            "file_size": os.path.getsize(self.filepath),
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
                "has_critical_loaders": False,
                "dll_count": 0,
                "all_functions": set(),
            }

        imports_by_dll = {}
        ordinal_count = 0
        ordinal_imports = []
        critical_loaders = []
        total_imports = 0
        all_functions = set()

        critical_loader_names = set(self.config.imports.critical_loaders)

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
                if func_name in critical_loader_names:
                    critical_loaders.append(
                        {
                            "dll": dll_name,
                            "function": func_name,
                        }
                    )

            imports_by_dll[dll_name] = functions

        ordinal_ratio = ordinal_count / total_imports if total_imports > 0 else 0.0

        return {
            "has_imports": True,
            "total_imports": total_imports,
            "imports_by_dll": imports_by_dll,
            "ordinal_count": ordinal_count,
            "ordinal_ratio": ordinal_ratio,
            "ordinal_imports": ordinal_imports,
            "critical_loaders": critical_loaders,
            "has_critical_loaders": len(critical_loaders) > 0,
            "dll_count": len(imports_by_dll),
            "all_functions": all_functions,
            "is_ordinal_heavy": ordinal_ratio
            > self.config.imports.ordinal_ratio_suspicious,
            "is_minimal": total_imports <= self.config.imports.minimal_import_count,
        }

    # ============================================================
    # Trust Signals (IMPROVED)
    # ============================================================

    def extract_trust_signals(self) -> Dict:
        """
        Extract indicators of legitimacy.
        Goal: Find reasons to TRUST this binary.

        Improved: More nuanced trust calculation.
        """
        # Digital signature
        has_signature = False
        signature_info = {}

        security_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        has_signature = security_dir.VirtualAddress > 0 and security_dir.Size > 0

        if has_signature:
            signature_info = {
                "offset": security_dir.VirtualAddress,
                "size": security_dir.Size,
            }

        # Version info / Manifest / Resources
        has_version_info = False
        has_manifest = False
        has_resources = False
        has_icon = False
        version_info = {}
        resource_types = []

        if hasattr(self.pe, "DIRECTORY_ENTRY_RESOURCE"):
            has_resources = True

            for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource_type.name is not None:
                    type_name = str(resource_type.name)
                else:
                    type_name = pefile.RESOURCE_TYPE.get(
                        resource_type.struct.Id, f"UNKNOWN_{resource_type.struct.Id}"
                    )

                resource_types.append(type_name)

                if type_name == "RT_VERSION":
                    has_version_info = True
                    version_info = self._extract_version_info()
                elif type_name == "RT_MANIFEST":
                    has_manifest = True
                elif type_name == "RT_ICON" or type_name == "RT_GROUP_ICON":
                    has_icon = True

        # File size analysis
        file_size = os.path.getsize(self.filepath)
        min_size_bytes = self.config.size.min_file_size_kb * 1024
        is_suspiciously_small = file_size < min_size_bytes

        # Calculate trust score
        trust_score = 0
        trust_reasons = []

        if has_signature:
            trust_score += self.config.trust.signature_weight
            trust_reasons.append("Digital signature present")

        if has_version_info:
            trust_score += self.config.trust.version_info_weight
            trust_reasons.append("Version info present")

        if has_manifest:
            trust_score += self.config.trust.manifest_weight
            trust_reasons.append("Manifest present")

        if has_resources and len(resource_types) > 2:
            trust_score += self.config.trust.resources_weight
            trust_reasons.append(f"Rich resources ({len(resource_types)} types)")

        # Determine trust level
        if has_signature and has_version_info and has_manifest:
            trust_level = "HIGH"
            trust_multiplier = self.config.trust.signed_with_metadata
        elif has_signature:
            trust_level = "MEDIUM"
            trust_multiplier = self.config.trust.signed_only
        else:
            trust_level = "LOW"
            trust_multiplier = self.config.trust.unsigned

        return {
            "has_signature": has_signature,
            "signature_info": signature_info,
            "has_version_info": has_version_info,
            "version_info": version_info,
            "has_manifest": has_manifest,
            "has_resources": has_resources,
            "has_icon": has_icon,
            "resource_types": resource_types,
            "file_size": file_size,
            "is_suspiciously_small": is_suspiciously_small,
            "has_bulk": has_version_info or has_manifest or has_resources,
            "trust_score": trust_score,
            "trust_level": trust_level,
            "trust_multiplier": trust_multiplier,
            "trust_reasons": trust_reasons,
        }

    def _extract_version_info(self) -> Dict:
        """Extract version information if available"""
        version_info = {}

        try:
            if hasattr(self.pe, "FileInfo"):
                for file_info in self.pe.FileInfo:
                    for entry in file_info:
                        if hasattr(entry, "StringTable"):
                            for st in entry.StringTable:
                                for key, value in st.entries.items():
                                    if isinstance(key, bytes):
                                        key = key.decode("utf-8", errors="ignore")
                                    if isinstance(value, bytes):
                                        value = value.decode("utf-8", errors="ignore")
                                    version_info[key] = value
        except:
            pass

        return version_info

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
            "uxtheme.dll",
        }

        network_dlls = {
            "ws2_32.dll",
            "wininet.dll",
            "winhttp.dll",
            "wsock32.dll",
            "mswsock.dll",
            "urlmon.dll",
            "dnsapi.dll",
        }

        crypto_dlls = {
            "advapi32.dll",  # Contains crypto APIs
            "crypt32.dll",
            "bcrypt.dll",
            "ncrypt.dll",
        }

        iat = self.extract_iat_analysis()
        imported_dlls = set(iat["imports_by_dll"].keys())

        has_ui_dlls = bool(ui_dlls & imported_dlls)
        has_network_dlls = bool(network_dlls & imported_dlls)
        has_crypto_dlls = bool(crypto_dlls & imported_dlls)

        # Check subsystem
        subsystem = self.pe.OPTIONAL_HEADER.Subsystem
        is_gui_subsystem = subsystem == 2  # IMAGE_SUBSYSTEM_WINDOWS_GUI
        is_console_subsystem = subsystem == 3  # IMAGE_SUBSYSTEM_WINDOWS_CUI

        # Subsystem names for reporting
        subsystem_names = {
            1: "Native",
            2: "Windows GUI",
            3: "Windows Console",
            5: "OS/2 Console",
            7: "POSIX Console",
            9: "Windows CE",
            10: "EFI Application",
            11: "EFI Boot Driver",
            12: "EFI Runtime Driver",
            13: "EFI ROM",
            14: "Xbox",
            16: "Windows Boot",
        }

        return {
            "has_ui_dlls": has_ui_dlls,
            "has_network_dlls": has_network_dlls,
            "has_crypto_dlls": has_crypto_dlls,
            "is_gui_subsystem": is_gui_subsystem,
            "is_console_subsystem": is_console_subsystem,
            "subsystem": subsystem,
            "subsystem_name": subsystem_names.get(subsystem, f"Unknown ({subsystem})"),
            "is_headless": has_network_dlls and not has_ui_dlls,
            "imported_dlls": imported_dlls,
            "dll_categories": {
                "ui": list(ui_dlls & imported_dlls),
                "network": list(network_dlls & imported_dlls),
                "crypto": list(crypto_dlls & imported_dlls),
            },
        }

    # ============================================================
    # Export Analysis (NEW)
    # ============================================================

    def extract_export_analysis(self) -> Dict:
        """
        Analyze exported functions.
        Goal: Detect DLL hijacking, proxying, and suspicious exports.
        """
        if not hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            return {
                "has_exports": False,
                "export_count": 0,
                "exports": [],
                "forwarders": [],
                "suspicious_exports": [],
                "is_suspicious": False,
                "dll_name": None,
            }

        exports = []
        forwarders = []
        suspicious_exports = []

        # Suspicious export name patterns
        suspicious_patterns = [
            "DllRegisterServer",
            "DllUnregisterServer",
            "DllCanUnloadNow",
            "DllGetClassObject",
            "ServiceMain",
            "StartServiceCtrlDispatcher",
        ]

        # Get DLL name if available
        dll_name = None
        if (
            hasattr(self.pe.DIRECTORY_ENTRY_EXPORT, "name")
            and self.pe.DIRECTORY_ENTRY_EXPORT.name
        ):
            dll_name = self.pe.DIRECTORY_ENTRY_EXPORT.name.decode(
                "utf-8", errors="ignore"
            )

        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            export_info = {
                "ordinal": exp.ordinal,
                "name": exp.name.decode("utf-8", errors="ignore") if exp.name else None,
                "address": hex(exp.address) if exp.address else None,
                "forwarder": None,
            }

            # Check for forwarders (DLL proxying)
            if exp.forwarder:
                forwarder = exp.forwarder.decode("utf-8", errors="ignore")
                export_info["forwarder"] = forwarder
                forwarders.append(
                    {
                        "name": export_info["name"],
                        "ordinal": exp.ordinal,
                        "forwards_to": forwarder,
                    }
                )

            exports.append(export_info)

            # Check for suspicious exports
            if export_info["name"]:
                for pattern in suspicious_patterns:
                    if pattern.lower() in export_info["name"].lower():
                        suspicious_exports.append(
                            {
                                "name": export_info["name"],
                                "reason": f"Matches suspicious pattern: {pattern}",
                            }
                        )
                        break

        # Determine if export table is suspicious
        is_suspicious = False
        suspicion_reasons = []

        # Many forwarders = possible DLL proxying attack
        if len(forwarders) > 5:
            is_suspicious = True
            suspicion_reasons.append(
                f"High forwarder count ({len(forwarders)}) - possible DLL proxying"
            )

        # High export count in non-UI binary
        if len(exports) > 50:
            is_suspicious = True
            suspicion_reasons.append(f"High export count ({len(exports)})")

        # Export by ordinal only (no names) can indicate hiding
        unnamed_exports = sum(1 for e in exports if e["name"] is None)
        if unnamed_exports > len(exports) * 0.5 and len(exports) > 10:
            is_suspicious = True
            suspicion_reasons.append(
                f"{unnamed_exports}/{len(exports)} exports unnamed (ordinal-only)"
            )

        return {
            "has_exports": True,
            "export_count": len(exports),
            "exports": exports[:50],  # Limit for large export tables
            "forwarders": forwarders,
            "forwarder_count": len(forwarders),
            "suspicious_exports": suspicious_exports,
            "is_suspicious": is_suspicious,
            "suspicion_reasons": suspicion_reasons,
            "dll_name": dll_name,
            "unnamed_ratio": unnamed_exports / len(exports) if exports else 0,
        }
