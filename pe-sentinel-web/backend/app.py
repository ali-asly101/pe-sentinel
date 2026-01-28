#!/usr/bin/env python3
"""
PE-Sentinel Web API v2.2.1
Fixes:
- PDF style conflict resolved
- Import analysis now informational only (no false positive warnings)
- Better JSON serialization to fix parse errors
- .NET runtime detection
"""

from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import sys
import re
import io
import json
from pathlib import Path
from datetime import datetime
import traceback
import hashlib

# Set up paths
ROOT_DIR = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(Path(__file__).parent))

print(f"[DEBUG] Root directory: {ROOT_DIR}")

from analyzer import BinaryAnalyzer
from core.config import AnalysisConfig, get_config
from core.pe_parser import PEAnalyzer

# Import new analyzers
try:
    from rich_header import RichHeaderAnalyzer, check_timestamp_anomaly

    RICH_HEADER_AVAILABLE = True
except ImportError:
    RICH_HEADER_AVAILABLE = False
    print("[WARN] Rich header analyzer not available")

try:
    from import_analyzer import ImportAnalyzer, analyze_imports

    IMPORT_ANALYZER_AVAILABLE = True
except ImportError:
    IMPORT_ANALYZER_AVAILABLE = False
    print("[WARN] Import analyzer not available")

try:
    from pdf_report import PDFReportGenerator, generate_pdf_report, REPORTLAB_AVAILABLE
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("[WARN] PDF report not available. Install: pip install reportlab")

try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

app = Flask(__name__)
CORS(app)

# Config
UPLOAD_FOLDER = ROOT_DIR / "pe-sentinel-web" / "uploads"
ALLOWED_EXTENSIONS = {"exe", "dll", "sys"}
MAX_FILE_SIZE = 50 * 1024 * 1024

UPLOAD_FOLDER.mkdir(exist_ok=True)
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

analyzed_files = {}
analysis_results = {}

CONFIG_PATH = ROOT_DIR / "config.json"
analysis_config = (
    get_config(str(CONFIG_PATH)) if CONFIG_PATH.exists() else AnalysisConfig()
)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def safe_serialize(obj, depth=0):
    """
    Recursively convert objects to JSON-safe types.
    Handles sets, bytes, custom objects, and circular references.
    """
    if depth > 50:  # Prevent infinite recursion
        return str(obj)

    if obj is None:
        return None
    elif isinstance(obj, (bool,)):
        return obj
    elif isinstance(obj, (int, float)):
        # Handle special float values
        if isinstance(obj, float):
            if obj != obj:  # NaN check
                return None
            if obj == float("inf") or obj == float("-inf"):
                return None
        return obj
    elif isinstance(obj, str):
        # Ensure string is valid UTF-8
        try:
            return obj.encode("utf-8", errors="replace").decode("utf-8")
        except:
            return str(obj)
    elif isinstance(obj, bytes):
        try:
            return obj.decode("utf-8", errors="replace")
        except:
            return obj.hex()
    elif isinstance(obj, (set, frozenset)):
        return [safe_serialize(item, depth + 1) for item in obj]
    elif isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            # Ensure key is a string
            key = str(k) if not isinstance(k, str) else k
            result[key] = safe_serialize(v, depth + 1)
        return result
    elif isinstance(obj, (list, tuple)):
        return [safe_serialize(item, depth + 1) for item in obj]
    elif hasattr(obj, "__dict__"):
        # Convert custom objects to dict
        return safe_serialize(obj.__dict__, depth + 1)
    elif hasattr(obj, "isoformat"):
        # Handle datetime objects
        return obj.isoformat()
    else:
        # Fallback: convert to string
        try:
            return str(obj)
        except:
            return None


def get_file_hash(filepath):
    with open(filepath, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def extract_strings_from_data(data: bytes, min_length: int = 4) -> list:
    strings = []
    ascii_pattern = rb"[\x20-\x7e]{%d,}" % min_length
    for match in re.finditer(ascii_pattern, data):
        try:
            strings.append(match.group().decode("ascii"))
        except:
            pass
    return strings


# ============================================================
# Static Routes
# ============================================================


@app.route("/")
def index():
    frontend_path = Path(__file__).parent.parent / "frontend"
    return send_from_directory(frontend_path, "index.html")


@app.route("/home")
def home():
    frontend_path = Path(__file__).parent.parent / "frontend"
    return send_from_directory(frontend_path, "home.html")


@app.route("/docs")
def docs():
    frontend_path = Path(__file__).parent.parent / "frontend"
    return send_from_directory(frontend_path, "docs.html")


@app.route("/js/<path:filename>")
def serve_js(filename):
    frontend_path = Path(__file__).parent.parent / "frontend"
    return send_from_directory(frontend_path / "js", filename)


@app.route("/css/<path:filename>")
def serve_css(filename):
    frontend_path = Path(__file__).parent.parent / "frontend"
    return send_from_directory(frontend_path / "css", filename)


# ============================================================
# Main Analysis
# ============================================================


@app.route("/api/upload", methods=["POST"])
def upload_file():
    print("[DEBUG] Upload endpoint hit")

    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file provided"}), 400

    file = request.files["file"]

    if file.filename == "" or not allowed_file(file.filename):
        return jsonify({"success": False, "error": "Invalid file"}), 400

    include_strings = request.form.get("include_strings", "true").lower() == "true"
    include_yara = request.form.get("include_yara", "true").lower() == "true"
    keep_file = request.form.get("keep_file", "true").lower() == "true"

    try:
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_filename = f"{timestamp}_{filename}"
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], unique_filename)

        file.save(filepath)
        file_hash = get_file_hash(filepath)

        print(f"[DEBUG] Analyzing {filepath}")

        # Main analysis
        analyzer = BinaryAnalyzer(filepath, analysis_config)
        results = analyzer.analyze(
            include_strings=include_strings, include_yara=include_yara
        )

        # ========================================
        # Rich Header Analysis
        # ========================================
        rich_header_result = {"present": False}
        if RICH_HEADER_AVAILABLE:
            try:
                with open(filepath, "rb") as f:
                    pe_data = f.read(8192)

                rich_analyzer = RichHeaderAnalyzer(pe_data)
                rich_result = rich_analyzer.analyze()

                pe_analyzer = PEAnalyzer(filepath)
                pe_timestamp = pe_analyzer.pe.FILE_HEADER.TimeDateStamp

                timestamp_check = check_timestamp_anomaly(rich_result, pe_timestamp)

                rich_header_result = {
                    "present": rich_result.present,
                    "valid": rich_result.valid,
                    "checksum": (
                        f"0x{rich_result.checksum:08X}"
                        if rich_result.checksum
                        else None
                    ),
                    "compiler_info": safe_serialize(rich_result.compiler_info),
                    "is_suspicious": rich_result.is_suspicious,
                    "suspicion_reasons": (
                        list(rich_result.suspicion_reasons)
                        if rich_result.suspicion_reasons
                        else []
                    ),
                    "warnings": (
                        list(rich_result.warnings) if rich_result.warnings else []
                    ),
                    "entries_count": len(rich_result.entries),
                    "entries": [
                        {
                            "tool_name": str(e.tool_name),
                            "tool_id": int(e.tool_id),
                            "tool_version": int(e.tool_version),
                            "use_count": int(e.use_count),
                        }
                        for e in rich_result.entries[:20]
                    ],
                    "timestamp_analysis": safe_serialize(timestamp_check),
                }

                print(
                    f"[DEBUG] Rich Header: {rich_result.compiler_info.get('visual_studio', 'Unknown')}"
                )

            except Exception as e:
                print(f"[WARN] Rich header analysis failed: {e}")
                rich_header_result = {"present": False, "error": str(e)}

        results["rich_header"] = rich_header_result

        # ========================================
        # Import Analysis (Informational Only)
        # ========================================
        import_analysis_result = {"info_only": True}
        if IMPORT_ANALYZER_AVAILABLE:
            try:
                pe_analyzer = PEAnalyzer(filepath)
                imports = pe_analyzer.get_imports()

                import_result = analyze_imports(imports)
                import_analysis_result = safe_serialize(import_result)

                runtime = import_result.get("runtime", {})
                print(f"[DEBUG] Runtime: {runtime.get('detected', 'Unknown')}")
                print(
                    f"[DEBUG] Imports: {import_result.get('density', {}).get('total_imports', 0)}"
                )

            except Exception as e:
                print(f"[WARN] Import analysis failed: {e}")
                import_analysis_result = {"error": str(e), "info_only": True}

        results["import_analysis"] = import_analysis_result

        print(f"[DEBUG] Analysis complete: {results['scores']['overall']}/100")

        # Store session
        if keep_file:
            analyzed_files[file_hash] = {
                "filepath": filepath,
                "filename": filename,
                "timestamp": datetime.now().isoformat(),
                "metadata": safe_serialize(results.get("metadata", {})),
            }
            analysis_results[file_hash] = results
            results["session_id"] = file_hash
        else:
            try:
                os.remove(filepath)
            except:
                pass

        # Safe serialize the entire result
        results = safe_serialize(results)
        results["success"] = True
        results["timestamp"] = datetime.now().isoformat()
        results["pdf_available"] = REPORTLAB_AVAILABLE

        # Verify JSON is valid before returning
        try:
            json.dumps(results)
        except (TypeError, ValueError) as e:
            print(f"[ERROR] JSON serialization failed: {e}")
            # Return minimal safe response
            return jsonify(
                {
                    "success": True,
                    "session_id": file_hash,
                    "scores": results.get("scores", {}),
                    "metadata": results.get("metadata", {}),
                    "warning": "Some data could not be serialized",
                }
            )

        return jsonify(results)

    except Exception as e:
        print(f"[ERROR] {str(e)}")
        print(traceback.format_exc())
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================
# PDF Export
# ============================================================


@app.route("/api/export/pdf/<session_id>", methods=["GET"])
def export_pdf(session_id):
    if not REPORTLAB_AVAILABLE:
        return (
            jsonify(
                {
                    "success": False,
                    "error": "PDF export not available. Install: pip install reportlab",
                }
            ),
            400,
        )

    if session_id not in analysis_results:
        return (
            jsonify(
                {
                    "success": False,
                    "error": "Session not found. Please re-analyze the file.",
                }
            ),
            404,
        )

    try:
        results = analysis_results[session_id]
        filename = results.get("metadata", {}).get("filename", "unknown")

        # Ensure data is serializable for PDF
        safe_results = safe_serialize(results)

        generator = PDFReportGenerator(safe_results)
        pdf_bytes = generator.generate()

        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"pe-sentinel-report-{filename}.pdf",
        )

    except Exception as e:
        print(f"[ERROR] PDF generation failed: {e}")
        print(traceback.format_exc())
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================
# Advanced Search
# ============================================================


@app.route("/api/search/functions", methods=["POST"])
def search_functions():
    data = request.json
    session_id = data.get("session_id")
    query = data.get("query", "")
    search_type = data.get("search_type", "contains")
    include_exports = data.get("include_exports", True)

    if not session_id or session_id not in analyzed_files:
        return jsonify({"success": False, "error": "Invalid session"}), 400

    if not query:
        return jsonify({"success": False, "error": "Query required"}), 400

    try:
        filepath = analyzed_files[session_id]["filepath"]
        pe_analyzer = PEAnalyzer(filepath)
        imports = pe_analyzer.get_imports()

        results = {"imports": [], "exports": []}

        if search_type == "exact":
            match_func = lambda name: name.lower() == query.lower()
        elif search_type == "regex":
            try:
                pattern = re.compile(query, re.IGNORECASE)
                match_func = lambda name: pattern.search(name) is not None
            except re.error as e:
                return jsonify({"success": False, "error": f"Invalid regex: {e}"}), 400
        else:
            match_func = lambda name: query.lower() in name.lower()

        for dll_entry in imports:
            dll_name = dll_entry.get("dll", "unknown")
            functions = dll_entry.get("functions", [])

            for func in functions:
                func_name = (
                    func.get("name", "") if isinstance(func, dict) else str(func)
                )
                if func_name and match_func(func_name):
                    results["imports"].append(
                        {
                            "dll": str(dll_name),
                            "function": str(func_name),
                            "ordinal": (
                                func.get("ordinal") if isinstance(func, dict) else None
                            ),
                        }
                    )

        if include_exports and hasattr(pe_analyzer.pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe_analyzer.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exp_name = exp.name.decode("utf-8", errors="ignore")
                    if match_func(exp_name):
                        results["exports"].append(
                            {
                                "function": str(exp_name),
                                "ordinal": int(exp.ordinal) if exp.ordinal else None,
                            }
                        )

        return jsonify(
            {
                "success": True,
                "query": query,
                "results": results,
                "total_imports": len(results["imports"]),
                "total_exports": len(results["exports"]),
            }
        )

    except Exception as e:
        print(f"[ERROR] {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/search/strings", methods=["POST"])
def search_strings():
    data = request.json
    session_id = data.get("session_id")
    query = data.get("query", "")
    search_type = data.get("search_type", "contains")
    min_length = data.get("min_length", 4)
    max_results = data.get("max_results", 200)

    if not session_id or session_id not in analyzed_files:
        return jsonify({"success": False, "error": "Invalid session"}), 400

    try:
        filepath = analyzed_files[session_id]["filepath"]

        with open(filepath, "rb") as f:
            raw_data = f.read()

        all_strings = extract_strings_from_data(raw_data, min_length)

        if search_type == "exact":
            match_func = lambda s: s.lower() == query.lower()
        elif search_type == "regex":
            try:
                pattern = re.compile(query, re.IGNORECASE)
                match_func = lambda s: pattern.search(s) is not None
            except re.error as e:
                return jsonify({"success": False, "error": f"Invalid regex: {e}"}), 400
        else:
            match_func = lambda s: query.lower() in s.lower() if query else True

        matched = [s for s in all_strings if match_func(s)][:max_results]

        return jsonify(
            {
                "success": True,
                "query": query,
                "total_strings": len(all_strings),
                "matched_count": len(matched),
                "strings": matched,
                "truncated": len(matched) >= max_results,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/search/yara", methods=["POST"])
def search_yara():
    if not YARA_AVAILABLE:
        return jsonify({"success": False, "error": "YARA not installed"}), 400

    data = request.json
    session_id = data.get("session_id")
    rules_text = data.get("rules", "")

    if not session_id or session_id not in analyzed_files:
        return jsonify({"success": False, "error": "Invalid session"}), 400

    if not rules_text.strip():
        return jsonify({"success": False, "error": "Rules required"}), 400

    try:
        filepath = analyzed_files[session_id]["filepath"]

        try:
            rules = yara.compile(source=rules_text)
        except yara.SyntaxError as e:
            return jsonify({"success": False, "error": f"YARA syntax error: {e}"}), 400

        matches = rules.match(filepath)

        results = []
        for match in matches:
            match_data = {
                "rule": str(match.rule),
                "tags": [str(t) for t in match.tags],
                "meta": (
                    {str(k): str(v) for k, v in match.meta.items()}
                    if match.meta
                    else {}
                ),
                "strings": [],
            }

            for string_match in match.strings:
                if hasattr(string_match, "instances"):
                    for instance in string_match.instances[:20]:  # Limit instances
                        match_data["strings"].append(
                            {
                                "identifier": str(string_match.identifier),
                                "offset": int(instance.offset),
                                "data": instance.matched_data.decode(
                                    "utf-8", errors="replace"
                                )[:100],
                            }
                        )
                else:
                    offset, identifier, matched_data = string_match
                    match_data["strings"].append(
                        {
                            "identifier": str(identifier),
                            "offset": int(offset),
                            "data": matched_data.decode("utf-8", errors="replace")[
                                :100
                            ],
                        }
                    )

            results.append(match_data)

        return jsonify(
            {"success": True, "matches": results, "total_matches": len(results)}
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/search/sections", methods=["POST"])
def search_sections():
    data = request.json
    session_id = data.get("session_id")
    filters = data.get("filter", {})

    if not session_id or session_id not in analyzed_files:
        return jsonify({"success": False, "error": "Invalid session"}), 400

    try:
        filepath = analyzed_files[session_id]["filepath"]
        analyzer_obj = BinaryAnalyzer(filepath, analysis_config)
        results = analyzer_obj.analyze(include_strings=False, include_yara=False)

        sections = results.get("sections", [])
        filtered = []

        for section in sections:
            include = True

            if (
                "min_entropy" in filters
                and section.get("entropy", 0) < filters["min_entropy"]
            ):
                include = False
            if (
                "max_entropy" in filters
                and section.get("entropy", 0) > filters["max_entropy"]
            ):
                include = False
            if (
                "permissions" in filters
                and filters["permissions"].upper()
                not in section.get("permissions", "").upper()
            ):
                include = False
            if filters.get("suspicious_only") and not section.get("is_suspicious"):
                include = False

            if include:
                filtered.append(safe_serialize(section))

        return jsonify(
            {
                "success": True,
                "total_sections": len(sections),
                "filtered_count": len(filtered),
                "sections": filtered,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/extract/iocs", methods=["POST"])
def extract_iocs():
    data = request.json
    session_id = data.get("session_id")

    if not session_id or session_id not in analyzed_files:
        return jsonify({"success": False, "error": "Invalid session"}), 400

    try:
        filepath = analyzed_files[session_id]["filepath"]
        analyzer_obj = BinaryAnalyzer(filepath, analysis_config)
        iocs = analyzer_obj.get_iocs()

        # Ensure all values are lists of strings
        safe_iocs = {}
        for key, value in iocs.items():
            if isinstance(value, (list, set)):
                safe_iocs[key] = [str(v) for v in value]
            else:
                safe_iocs[key] = []

        total = sum(len(v) for v in safe_iocs.values())

        return jsonify(
            {
                "success": True,
                "iocs": safe_iocs,
                "total": total,
                "filename": analyzed_files[session_id]["filename"],
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/hexdump", methods=["POST"])
def get_hexdump():
    data = request.json
    session_id = data.get("session_id")
    section_name = data.get("section")
    offset = data.get("offset", 0)
    length = min(data.get("length", 256), 4096)

    if not session_id or session_id not in analyzed_files:
        return jsonify({"success": False, "error": "Invalid session"}), 400

    try:
        filepath = analyzed_files[session_id]["filepath"]
        pe_analyzer = PEAnalyzer(filepath)

        if section_name:
            for section in pe_analyzer.pe.sections:
                name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
                if name == section_name:
                    data_bytes = section.get_data()[:length]
                    offset = section.PointerToRawData
                    break
            else:
                return (
                    jsonify(
                        {"success": False, "error": f"Section {section_name} not found"}
                    ),
                    404,
                )
        else:
            with open(filepath, "rb") as f:
                f.seek(offset)
                data_bytes = f.read(length)

        lines = []
        for i in range(0, len(data_bytes), 16):
            chunk = data_bytes[i : i + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(
                {"offset": f"{offset + i:08x}", "hex": hex_part, "ascii": ascii_part}
            )

        return jsonify(
            {
                "success": True,
                "offset": offset,
                "length": len(data_bytes),
                "lines": lines,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================
# Session & Health
# ============================================================


@app.route("/api/session/<session_id>", methods=["GET"])
def get_session(session_id):
    if session_id not in analyzed_files:
        return jsonify({"success": False, "error": "Not found"}), 404
    return jsonify({"success": True, **safe_serialize(analyzed_files[session_id])})


@app.route("/api/session/<session_id>", methods=["DELETE"])
def delete_session(session_id):
    if session_id not in analyzed_files:
        return jsonify({"success": False, "error": "Not found"}), 404
    try:
        os.remove(analyzed_files[session_id]["filepath"])
    except:
        pass
    del analyzed_files[session_id]
    if session_id in analysis_results:
        del analysis_results[session_id]
    return jsonify({"success": True})


@app.route("/api/sessions", methods=["GET"])
def list_sessions():
    return jsonify(
        {
            "success": True,
            "sessions": [
                {
                    "session_id": sid,
                    "filename": info["filename"],
                    "timestamp": info["timestamp"],
                }
                for sid, info in analyzed_files.items()
            ],
        }
    )


@app.route("/api/health")
def health():
    return jsonify(
        {
            "status": "healthy",
            "version": "2.2.1",
            "features": {
                "string_analysis": True,
                "yara_scanning": YARA_AVAILABLE,
                "mitre_mapping": True,
                "function_search": True,
                "hexdump": True,
                "rich_header": RICH_HEADER_AVAILABLE,
                "import_analysis": IMPORT_ANALYZER_AVAILABLE,
                "pdf_export": REPORTLAB_AVAILABLE,
                "dark_mode": True,
            },
            "active_sessions": len(analyzed_files),
        }
    )


if __name__ == "__main__":
    print("=" * 60)
    print("PE-Sentinel Web Server v2.2.1")
    print("=" * 60)
    print(f"🚀 http://localhost:5000")
    print(f"📁 Uploads: {UPLOAD_FOLDER}")
    print(f"\n🔬 Features:")
    print(f"   YARA: {'✓' if YARA_AVAILABLE else '✗'}")
    print(f"   Rich Header: {'✓' if RICH_HEADER_AVAILABLE else '✗'}")
    print(f"   Import Analyzer: {'✓' if IMPORT_ANALYZER_AVAILABLE else '✗'}")
    print(f"   PDF Export: {'✓' if REPORTLAB_AVAILABLE else '✗'}")
    print(f"\n📄 Pages: /home, /docs, /")
    print("⚠️  Development only\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
