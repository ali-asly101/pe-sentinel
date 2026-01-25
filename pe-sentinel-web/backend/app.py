#!/usr/bin/env python3
"""
PE-Sentinel Web API
Flask backend for malware analysis web interface
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import sys
from pathlib import Path
from datetime import datetime
import traceback

# Set up paths FIRST (before any imports from core)
ROOT_DIR = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

print(f"[DEBUG] Root directory: {ROOT_DIR}")
print(f"[DEBUG] Core exists: {(ROOT_DIR / 'core').exists()}")

# Now import core modules
from core.pe_parser import PEAnalyzer
from core.analyzers import SectionAnalyzer
from core.sentinel.extractors import FeatureExtractor
from core.sentinel.correlators import CorrelationEngine
from core.sentinel.verdict_engine import VerdictEngine
from core.sentinel.mitre_mapper import MitreMapper

app = Flask(__name__)
CORS(app)

# Configuration
UPLOAD_FOLDER = ROOT_DIR / "pe-sentinel-web" / "uploads"
ALLOWED_EXTENSIONS = {"exe", "dll", "sys"}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

UPLOAD_FOLDER.mkdir(exist_ok=True)
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE


def allowed_file(filename):
    """Check if file extension is allowed"""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def serialize_for_json(obj):
    """
    Convert non-JSON-serializable objects to JSON-compatible types
    Handles: sets, custom objects, etc.
    """
    if isinstance(obj, set):
        return list(obj)
    elif isinstance(obj, dict):
        return {k: serialize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [serialize_for_json(item) for item in obj]
    else:
        return obj


# Routes for serving frontend files
@app.route("/")
def index():
    """Serve main page"""
    frontend_path = Path(__file__).parent.parent / "frontend"
    return send_from_directory(frontend_path, "index.html")


@app.route("/js/<path:filename>")
def serve_js(filename):
    """Serve JavaScript files"""
    frontend_path = Path(__file__).parent.parent / "frontend"
    return send_from_directory(frontend_path / "js", filename)


@app.route("/css/<path:filename>")
def serve_css(filename):
    """Serve CSS files"""
    frontend_path = Path(__file__).parent.parent / "frontend"
    return send_from_directory(frontend_path / "css", filename)


@app.route("/api/upload", methods=["POST"])
def upload_file():
    """Handle file upload and analysis"""
    print("[DEBUG] Upload endpoint hit")

    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file provided"}), 400

    file = request.files["file"]
    print(f"[DEBUG] File received: {file.filename}")

    if file.filename == "":
        return jsonify({"success": False, "error": "No file selected"}), 400

    if not allowed_file(file.filename):
        return (
            jsonify(
                {
                    "success": False,
                    "error": "Invalid file type. Only .exe, .dll, .sys allowed",
                }
            ),
            400,
        )

    try:
        # Save file
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_filename = f"{timestamp}_{filename}"
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], unique_filename)

        print(f"[DEBUG] Saving to: {filepath}")
        file.save(filepath)

        print("[DEBUG] Starting analysis...")

        # Analyze PE file
        pe_analyzer = PEAnalyzer(filepath)
        sections = pe_analyzer.get_sections()
        metadata = pe_analyzer.get_metadata()

        print(f"[DEBUG] Found {len(sections)} sections")

        # Section analysis
        section_analyses = []
        for section in sections:
            analysis = SectionAnalyzer.analyze_section(section)

            # Serialize segment_analysis to ensure JSON compatibility
            segment_analysis = serialize_for_json(analysis.segment_analysis)

            section_analyses.append(
                {
                    "name": analysis.name,
                    "entropy": float(analysis.entropy),
                    "entropy_status": analysis.entropy_status,
                    "size_ratio": float(analysis.size_ratio),
                    "permissions": analysis.permissions,
                    "suspicion_score": int(analysis.suspicion_score),
                    "suspicion_level": analysis.suspicion_level,
                    "warnings": list(analysis.warnings),
                    "is_suspicious": bool(analysis.is_suspicious),
                    "segment_analysis": segment_analysis,
                    "virtual_size": int(section["virtual_size"]),
                    "raw_size": int(section["raw_size"]),
                }
            )

        section_max_score = (
            max(s["suspicion_score"] for s in section_analyses)
            if section_analyses
            else 0
        )

        print("[DEBUG] Running behavioral analysis...")

        # Behavioral analysis
        extractor = FeatureExtractor(filepath)
        features = extractor.extract_all()

        # Convert section_analyses to SectionAnalysis objects for correlation
        from core.analyzers import SectionAnalysis

        section_objs = [
            SectionAnalysis(
                name=sa["name"],
                entropy=sa["entropy"],
                entropy_status=sa["entropy_status"],
                size_ratio=sa["size_ratio"],
                size_status="",
                permissions=sa["permissions"],
                permission_status="",
                suspicion_score=sa["suspicion_score"],
                suspicion_level=sa["suspicion_level"],
                warnings=sa["warnings"],
                is_suspicious=sa["is_suspicious"],
                segment_analysis=sa["segment_analysis"],
            )
            for sa in section_analyses
        ]

        correlation = CorrelationEngine.correlate(features, section_objs)

        # Generate verdict with structural score for attribution
        verdict = VerdictEngine.generate_verdict(
            features, correlation, structural_score=section_max_score
        )

        # Get MITRE ATT&CK mappings
        mitre_techniques = MitreMapper.map_capabilities(correlation["capabilities"])
        mitre_matrix = MitreMapper.generate_attack_matrix(mitre_techniques)

        # Calculate overall threat score
        structural_score = section_max_score
        behavioral_score = verdict["final_score"]
        has_signature = features["trust_signals"]["has_signature"]
        has_bulk = features["trust_signals"]["has_bulk"]

        # Weighted scoring based on trust signals
        if has_signature and has_bulk:
            overall_score = int(structural_score * 0.3 + behavioral_score * 0.7)
        elif has_signature:
            overall_score = int(structural_score * 0.4 + behavioral_score * 0.6)
        else:
            overall_score = max(structural_score, behavioral_score)

        # Determine threat level
        if overall_score >= 80:
            threat_level = "CRITICAL"
            threat_color = "#dc3545"
        elif overall_score >= 60:
            threat_level = "HIGH"
            threat_color = "#fd7e14"
        elif overall_score >= 40:
            threat_level = "MEDIUM"
            threat_color = "#ffc107"
        elif overall_score >= 20:
            threat_level = "LOW"
            threat_color = "#28a745"
        else:
            threat_level = "CLEAN"
            threat_color = "#20c997"

        print(
            f"[DEBUG] Analysis complete! Threat: {overall_score}/100 ({threat_level})"
        )
        print(
            f"[DEBUG] Primary threat driver: {verdict.get('primary_driver', 'Unknown')}"
        )
        print(f"[DEBUG] MITRE techniques detected: {len(mitre_techniques)}")

        # Clean up uploaded file
        try:
            os.remove(filepath)
            print("[DEBUG] Temp file deleted")
        except Exception as e:
            print(f"[DEBUG] Could not delete temp file: {e}")

        # Serialize ui_indicators (might contain sets)
        ui_indicators_serialized = serialize_for_json(features["ui_indicators"])

        # Build response
        results = {
            "success": True,
            "metadata": metadata,
            "scores": {
                "structural": structural_score,
                "behavioral": behavioral_score,
                "overall": overall_score,
                "threat_level": threat_level,
                "threat_color": threat_color,
                "attribution": verdict.get("attribution", {}),
                "primary_driver": verdict.get("primary_driver", "Unknown"),
            },
            "mitre": {
                "techniques": mitre_techniques,
                "matrix": mitre_matrix,
                "total_techniques": len(mitre_techniques),
            },
            "sections": section_analyses,
            "features": {
                "iat_analysis": {
                    "total_imports": features["iat_analysis"]["total_imports"],
                    "dll_count": features["iat_analysis"]["dll_count"],
                    "ordinal_count": features["iat_analysis"]["ordinal_count"],
                    "ordinal_ratio": float(features["iat_analysis"]["ordinal_ratio"]),
                    "has_critical_loaders": len(
                        features["iat_analysis"].get("critical_loaders", [])
                    )
                    > 0,
                },
                "ui_indicators": ui_indicators_serialized,
                "trust_signals": features["trust_signals"],
            },
            "capabilities": [
                {
                    "description": cap["description"],
                    "score": cap["final_score"],
                    "matched_apis": cap["matched_apis"],
                    "is_obfuscated": cap["is_obfuscated"],
                }
                for cap in correlation["capabilities"]
            ],
            "verdict": {
                "reasons": verdict["reasons"],
                "is_likely_malicious": verdict["is_likely_malicious"],
            },
            "timestamp": datetime.now().isoformat(),
        }

        print("[DEBUG] Sending response...")
        return jsonify(results)

    except Exception as e:
        print(f"[ERROR] {str(e)}")
        print(traceback.format_exc())
        return (
            jsonify(
                {"success": False, "error": str(e), "traceback": traceback.format_exc()}
            ),
            500,
        )


@app.route("/api/health")
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "version": "1.0.0"})


if __name__ == "__main__":
    print("=" * 70)
    print("PE-Sentinel Web Server")
    print("=" * 70)
    print(f"\n🚀 Starting server on http://localhost:5000")
    print(f"📁 Upload folder: {UPLOAD_FOLDER}")
    print("\n⚠️  WARNING: For development only. Do NOT use in production.\n")

    app.run(debug=True, host="0.0.0.0", port=5000)
