"""
Import Analysis Module
Advanced import table analysis for malware detection:
- Import Density Scoring (detect packers/stagers)
- Ordinal Ratio Analysis (detect API hiding)
- .NET Runtime Detection (avoid false positives)

NOTE: This module provides INFORMATIONAL analysis only.
Warnings have been removed to avoid false positives with legitimate software
like .NET applications, Go binaries, and other runtimes.
"""

from typing import Dict, List, Tuple
from dataclasses import dataclass


@dataclass
class ImportDensityResult:
    """Import density analysis result"""

    total_imports: int
    dll_count: int
    density_level: str  # MINIMAL, LOW, NORMAL, HIGH
    is_dotnet: bool
    is_go: bool
    runtime_detected: str  # .NET, Go, Native, Unknown
    pattern: str  # RUNTIME, NATIVE, PACKED_MAYBE


@dataclass
class OrdinalAnalysisResult:
    """Ordinal import analysis result"""

    total_imports: int
    ordinal_imports: int
    ordinal_ratio: float


# .NET Runtime DLLs
DOTNET_DLLS = {
    "mscoree.dll",
    "mscorlib.dll",
    "clr.dll",
    "clrjit.dll",
    "coreclr.dll",
    "hostfxr.dll",
    "hostpolicy.dll",
}

# .NET entry point functions
DOTNET_FUNCTIONS = {
    "_CorExeMain",
    "_CorDllMain",
    "CorExeMain",
    "CorDllMain",
}

# Go runtime indicators
GO_DLLS = {
    "kernel32.dll",  # Go uses kernel32 heavily
}

GO_FUNCTIONS = {
    "GetProcAddress",
    "LoadLibraryA",
    "GetModuleHandleA",
    "VirtualAlloc",
    "VirtualFree",
    "SetUnhandledExceptionFilter",
}

# Critical loader functions
CRITICAL_LOADERS = {
    "LoadLibraryA",
    "LoadLibraryW",
    "LoadLibraryExA",
    "LoadLibraryExW",
    "GetProcAddress",
    "GetModuleHandleA",
    "GetModuleHandleW",
    "LdrLoadDll",
    "LdrGetProcedureAddress",
}


class ImportAnalyzer:
    """Analyze imports - informational only, no warnings to avoid false positives"""

    def __init__(self, imports: List[Dict]):
        """
        Args:
            imports: List of {dll: str, functions: List[{name, ordinal, address}]}
        """
        self.imports = imports

    def analyze(self) -> Dict:
        """Perform import analysis - returns info without suspicion scoring"""

        # Count totals
        total_imports = 0
        dll_count = len(self.imports)
        all_functions = set()
        all_dlls = set()
        ordinal_imports = 0

        for dll_entry in self.imports:
            dll_name = dll_entry.get("dll", "").lower()
            all_dlls.add(dll_name)
            functions = dll_entry.get("functions", [])

            for func in functions:
                total_imports += 1

                if isinstance(func, dict):
                    name = func.get("name", "")
                    # Check if ordinal import
                    if not name or name.startswith("Ordinal_") or str(name).isdigit():
                        ordinal_imports += 1
                    if name:
                        all_functions.add(name)
                else:
                    name = str(func)
                    if name.startswith("Ordinal_") or name.isdigit():
                        ordinal_imports += 1
                    all_functions.add(name)

        # Detect runtime
        is_dotnet = self._detect_dotnet(all_dlls, all_functions)
        is_go = self._detect_go(all_dlls, all_functions, total_imports)

        if is_dotnet:
            runtime_detected = ".NET"
        elif is_go:
            runtime_detected = "Go"
        elif total_imports > 20:
            runtime_detected = "Native"
        else:
            runtime_detected = "Unknown"

        # Determine density level (informational only)
        if total_imports <= 5:
            density_level = "MINIMAL"
        elif total_imports <= 15:
            density_level = "LOW"
        elif total_imports <= 500:
            density_level = "NORMAL"
        else:
            density_level = "HIGH"

        # Determine pattern
        if is_dotnet or is_go:
            pattern = "RUNTIME"
        elif total_imports > 15:
            pattern = "NATIVE"
        else:
            pattern = "MINIMAL_IAT"

        # Calculate ordinal ratio
        ordinal_ratio = ordinal_imports / total_imports if total_imports > 0 else 0

        # Check for loader functions
        loader_funcs = all_functions & CRITICAL_LOADERS
        has_loaders = len(loader_funcs) > 0

        return {
            "density": {
                "total_imports": total_imports,
                "dll_count": dll_count,
                "level": density_level,
                "pattern": pattern,
            },
            "ordinal": {
                "total": total_imports,
                "ordinal_count": ordinal_imports,
                "ratio": ordinal_ratio,
                "ratio_percent": f"{ordinal_ratio * 100:.1f}%",
            },
            "runtime": {
                "detected": runtime_detected,
                "is_dotnet": is_dotnet,
                "is_go": is_go,
                "is_native": not is_dotnet and not is_go,
            },
            "loaders": {
                "has_critical_loaders": has_loaders,
                "loader_functions": list(loader_funcs),
            },
            # No scoring or warnings - just informational
            "info_only": True,
            "note": "Import analysis is informational. Low import counts may indicate .NET, Go, or other runtime-based applications.",
        }

    def _detect_dotnet(self, dlls: set, functions: set) -> bool:
        """Detect if this is a .NET application"""
        # Check for .NET DLLs
        if dlls & DOTNET_DLLS:
            return True

        # Check for .NET entry points
        if functions & DOTNET_FUNCTIONS:
            return True

        # Check for mscoree.dll specifically (most common)
        if "mscoree.dll" in dlls:
            return True

        return False

    def _detect_go(self, dlls: set, functions: set, total_imports: int) -> bool:
        """Detect if this is a Go application"""
        # Go binaries typically have specific patterns
        # They often have many imports from kernel32.dll

        if "kernel32.dll" in dlls:
            go_funcs = functions & GO_FUNCTIONS
            # Go typically imports these specific functions
            if len(go_funcs) >= 4:
                return True

        return False


def analyze_imports(imports: List[Dict]) -> Dict:
    """Convenience function for import analysis"""
    analyzer = ImportAnalyzer(imports)
    return analyzer.analyze()
