<p align="center">
  <img src="docs/images/logo.png" alt="PE-Sentinel Logo" width="120">
  <h1 align="center">PE-Sentinel</h1>
  <p align="center">
    <strong>Advanced Static Malware Analysis Platform</strong>
  </p>
  <p align="center">
    <a href="#features">Features</a> •
    <a href="#installation">Installation</a> •
    <a href="#usage">Usage</a> •
    <a href="#api">API</a> •
    <a href="#contributing">Contributing</a>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python">
    <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
    <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg" alt="Platform">
  </p>
</p>

---

PE-Sentinel is a comprehensive static analysis tool for Windows Portable Executable (PE) files. It performs deep inspection of binary structure, import tables, and behavioral patterns to identify potential malware without execution.

<p align="center">
  <img src="docs/images/screenshot.png" alt="PE-Sentinel Dashboard" width="800">
</p>

## 🎯 Key Capabilities

- **Zero Execution Risk** - Entirely static analysis, no sandboxing required
- **Rich Header Forensics** - Parse undocumented Microsoft Rich headers for compiler fingerprinting and timestamp manipulation detection
- **Import Table Intelligence** - Density scoring, ordinal ratio analysis, and .NET/Go runtime detection
- **MITRE ATT&CK Mapping** - Automatic technique identification with confidence scoring
- **YARA Integration** - Built-in rules plus custom rule support
- **Professional Reports** - Export to PDF, JSON, Markdown, HTML, or SARIF

## ✨ Features

### Structural Analysis
- Section entropy calculation with segment-level granularity
- Packer/crypter detection via entropy heuristics
- Permission anomaly detection (RWX sections)
- Size ratio analysis for section inflation detection

### Behavioral Analysis
- API capability correlation (50+ malicious patterns)
- Process injection detection
- Keylogger indicators
- Ransomware behavior patterns
- Credential theft techniques
- Anti-debug/anti-VM detection

### Rich Header Analysis
- Compiler/linker tool identification
- Visual Studio version detection
- Timestamp anomaly detection (time-stomping)
- Build environment fingerprinting

### Import Analysis
- Import density scoring
- Ordinal import ratio detection
- Runtime detection (.NET, Go, Native)
- Manual loader function identification

### Trust Verification
- Digital signature validation
- Version information extraction
- Manifest analysis
- Authenticode verification

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/pe-sentinel.git
cd pe-sentinel

# Install dependencies
pip install -r requirements.txt

# Run analysis
python analyze.py sample.exe
```

### Optional Dependencies

```bash
# YARA support (recommended)
pip install yara-python

# PDF report generation
pip install reportlab

# Disassembly support
pip install capstone
```


## 🚀 Usage

### Command Line

```bash
# Basic analysis
python analyze.py malware.exe

# Generate PDF report
python analyze.py malware.exe -o report.pdf -f pdf

# Quiet mode (minimal output)
python analyze.py malware.exe -q

# JSON output for automation
python analyze.py malware.exe -f json > results.json

# SARIF output for CI/CD integration
python analyze.py malware.exe -f sarif -o results.sarif
```

### Interactive Mode

```bash
python cli.py suspicious.exe
```

Available commands:
```python
show_summary()         # File overview
show_sections()        # Section analysis with entropy
show_imports()         # Import table with suspicious API highlighting
show_threat_analysis() # Detailed threat assessment
find_strings()         # Extract ASCII/Unicode strings
search_import("Create") # Search for specific imports
hexdump(0x1000, 256)   # View hex dump at offset
```

### Web Interface

```bash
cd pe-sentinel-web/backend
python app.py
# Open http://localhost:5000
```

## 📊 Analysis Output

```
══════════════════════════════════════════════════════════════════
                         PE-SENTINEL v2.2
              Advanced Static Malware Analysis
══════════════════════════════════════════════════════════════════

PHASE 1: STRUCTURAL ANALYSIS
────────────────────────────────────────────────────────────────
Section      Entropy    Ratio    Perms    Score    Level
.text        6.45       1.00     R-X      15       🟢 LOW
.rdata       5.12       0.89     R--      5        ✅ CLEAN
.data        4.23       0.45     RW-      10       ✅ CLEAN
.rsrc        7.89       1.23     R--      65       🟠 HIGH

PHASE 2: RICH HEADER ANALYSIS
────────────────────────────────────────────────────────────────
Compiler: Visual Studio 2019
Build: 29335
Timestamp Check: ✓ CONSISTENT

PHASE 3: IMPORT ANALYSIS
────────────────────────────────────────────────────────────────
Total Imports: 47
Runtime: Native
Ordinal Ratio: 2.1%

PHASE 4: BEHAVIORAL ANALYSIS
────────────────────────────────────────────────────────────────
⚠️  Process Injection capability detected
    APIs: OpenProcess, VirtualAllocEx, WriteProcessMemory

PHASE 5: MITRE ATT&CK MAPPING
────────────────────────────────────────────────────────────────
T1055 - Process Injection (Defense Evasion)
T1056.001 - Keylogging (Collection)

PHASE 6: FINAL VERDICT
────────────────────────────────────────────────────────────────
🔴 THREAT SCORE: 72/100 (HIGH)
Primary Driver: Behavioral indicators
Recommendation: Submit to sandbox for dynamic analysis
```

## 🔌 API Reference

### REST API

```bash
# Upload and analyze
curl -X POST -F "file=@sample.exe" http://localhost:5000/api/upload

# Search functions
curl -X POST -H "Content-Type: application/json" \
  -d '{"session_id":"abc123","query":"CreateRemote"}' \
  http://localhost:5000/api/search/functions

# Export PDF
curl http://localhost:5000/api/export/pdf/{session_id} -o report.pdf
```

### Python API

```python
from analyzer import BinaryAnalyzer

analyzer = BinaryAnalyzer("sample.exe")
results = analyzer.analyze()

print(f"Threat Score: {results['scores']['overall']}/100")
print(f"Threat Level: {results['scores']['threat_level']}")

for cap in results['capabilities']:
    print(f"  - {cap['description']}")
```

## 🏗️ Architecture

```
pe-sentinel/
├── core/                    # Core analysis modules
│   ├── pe_parser.py        # PE file parsing
│   ├── config.py           # Configuration management
│   └── sentinel/           # Analysis engines
│       ├── correlators.py  # API correlation
│       ├── extractors.py   # Data extraction
│       ├── mitre_mapper.py # MITRE ATT&CK mapping
│       └── verdict_engine.py
├── pe-sentinel-web/        # Web interface
│   ├── backend/
│   │   ├── app.py          # Flask API
│   │   ├── analyzer.py     # Analysis wrapper
│   │   ├── rich_header.py  # Rich header parser
│   │   ├── import_analyzer.py
│   │   └── pdf_report.py   # PDF generation
│   └── frontend/
│       ├── index.html      # Main analyzer UI
│       ├── home.html       # Landing page
│       ├── docs.html       # Documentation
│       └── js/main.js      # Frontend logic
├── analyze.py              # CLI entry point
├── cli.py                  # Interactive mode
└── requirements.txt
```

## 🔬 Technical Details

### Scoring System

| Component | Weight | Max Score | Description |
|-----------|--------|-----------|-------------|
| Structural | 30% | 100 | Entropy, permissions, section anomalies |
| Behavioral | 50% | 100 | API patterns, capability correlation |
| Strings | 10% | 40 | Suspicious string patterns |
| YARA | 10% | 100 | Rule matches |

### Threat Levels

| Level | Score Range | Interpretation |
|-------|-------------|----------------|
| CRITICAL | 80-100 | Highly likely malicious |
| HIGH | 60-79 | Probably malicious |
| MEDIUM | 40-59 | Suspicious, needs review |
| LOW | 20-39 | Minor concerns |
| CLEAN | 0-19 | Likely benign |

## 📄 License

This project is licensed under the MIT License

## 🙏 Acknowledgments

- [pefile](https://github.com/erocarrera/pefile) - PE parsing library
- [YARA](https://virustotal.github.io/yara/) - Pattern matching
- [MITRE ATT&CK](https://attack.mitre.org/) - Threat framework
- [Capstone](https://www.capstone-engine.org/) - Disassembly

## 📬 Contact

**Your Name** - aliomaruniversity@gmail.com

Project Link: [https://github.com/ali-asly101/pe-sentinel](https://github.com/ali-asly101/pe-sentinel)

---

<p align="center">
  <sub>Built with ☕ for the security community</sub>
</p>