"""
Phase 3: Indiscrepancy Filter & Final Verdict
Detects contradictions and applies trust reduction.
Now integrates string analysis results.
"""

from typing import Dict, Tuple, List, Optional

from ..config import AnalysisConfig, DEFAULT_CONFIG
from ..string_analyzer import StringAnalysisResult


class IndiscrepancyFilter:
    """Detect contradictions that indicate malicious intent"""

    def __init__(self, config: AnalysisConfig = None):
        self.config = config or DEFAULT_CONFIG

    def calculate_indiscrepancy_score(
        self, features: Dict, correlation: Dict
    ) -> Tuple[int, List[str]]:
        """
        Calculate indiscrepancy score based on contradictions.

        High score = High contradiction = Likely malicious
        """
        score = 0
        reasons = []

        ui_indicators = features["ui_indicators"]
        trust_signals = features["trust_signals"]
        iat = features["iat_analysis"]
        export_analysis = features.get("export_analysis", {})

        # ======================================
        # Check 1: "Headless" Network Binary
        # ======================================
        if ui_indicators["is_headless"]:
            score += 30
            reasons.append(
                "HEADLESS: Network capabilities without UI (suspicious for non-service binary)"
            )

        # ======================================
        # Check 2: High-Privilege Combos + No Bulk
        # ======================================
        has_dangerous_capabilities = correlation["total_capability_score"] > 30
        has_no_bulk = (
            not trust_signals["has_bulk"] and trust_signals["is_suspiciously_small"]
        )

        if has_dangerous_capabilities and has_no_bulk:
            score += 25
            reasons.append(
                "NO BULK: Dangerous capabilities but no version info/manifest (malicious stub pattern)"
            )

        # ======================================
        # Check 3: Minimal Imports (Manual Resolution)
        # ======================================
        if iat.get("is_minimal", False) and iat.get("has_critical_loaders", False):
            score += 20
            reasons.append(
                f"MINIMAL IMPORTS: Only {iat['total_imports']} imports with manual loaders (hiding behavior)"
            )

        # ======================================
        # Check 4: Ordinal Hiding
        # ======================================
        if iat.get("is_ordinal_heavy", False):
            score += 15
            reasons.append(
                f"ORDINAL HIDING: {iat['ordinal_ratio']*100:.0f}% of imports by ordinal (evading string detection)"
            )

        # ======================================
        # Check 5: No Imports at All
        # ======================================
        if not iat.get("has_imports", True):
            score += 25
            reasons.append(
                "NO IMPORTS: Binary has no import table (packed or self-contained)"
            )

        # ======================================
        # Check 6: Suspicious Exports (NEW)
        # ======================================
        if export_analysis.get("is_suspicious", False):
            for reason in export_analysis.get("suspicion_reasons", []):
                score += 10
                reasons.append(f"EXPORT ANOMALY: {reason}")

        # ======================================
        # Check 7: Console app with GUI capabilities but network
        # ======================================
        if (
            ui_indicators.get("is_console_subsystem")
            and ui_indicators.get("has_network_dlls")
            and not ui_indicators.get("has_ui_dlls")
        ):
            # Console + network + no UI is common for malware
            if has_dangerous_capabilities:
                score += 15
                reasons.append(
                    "CONSOLE DROPPER: Console subsystem with network but no UI + dangerous capabilities"
                )

        return min(self.config.scoring.max_indiscrepancy_score, score), reasons

    def apply_trust_reduction(
        self, base_score: int, features: Dict
    ) -> Tuple[int, str, float]:
        """
        Apply trust-based score reduction.

        IMPROVED: More nuanced reduction based on multiple trust signals.
        """
        trust_signals = features["trust_signals"]

        # Use pre-calculated trust multiplier from extractor
        multiplier = trust_signals.get("trust_multiplier", 1.0)
        trust_level = trust_signals.get("trust_level", "LOW")

        if multiplier < 1.0:
            reduced_score = int(base_score * multiplier)
            reduction_pct = (1 - multiplier) * 100

            reason = (
                f"Trust reduction: {reduction_pct:.0f}% "
                f"(Level: {trust_level}, "
                f"Score: {base_score} → {reduced_score})"
            )

            trust_reasons = trust_signals.get("trust_reasons", [])
            if trust_reasons:
                reason += f"\n  Factors: {', '.join(trust_reasons)}"

            return reduced_score, reason, multiplier

        return (
            base_score,
            "No trust reduction (unsigned or insufficient trust signals)",
            1.0,
        )


class VerdictEngine:
    """Final verdict generator with threat attribution"""

    def __init__(self, config: AnalysisConfig = None):
        self.config = config or DEFAULT_CONFIG
        self.indiscrepancy_filter = IndiscrepancyFilter(config)

    def get_score_attribution(
        self,
        features: Dict,
        correlation: Dict,
        indiscrepancy_score: int,
        structural_score: int,
        string_score: int = 0,
    ) -> Tuple[Dict, str]:
        """
        Calculate threat score attribution across five pillars.

        Returns:
            (attribution_dict, primary_driver)
        """
        cfg = self.config.scoring

        # Map scores to threat pillars
        attribution = {
            "Capabilities": min(50, correlation["total_capability_score"]),
            "Stealth": 0,  # Will calculate below
            "Integrity": 0,  # Will calculate below
            "Intent": min(30, indiscrepancy_score),
            "Strings": min(30, string_score),  # NEW
        }

        # Calculate Integrity score (trust deficit)
        integrity_score = 0
        if not features["trust_signals"]["has_signature"]:
            integrity_score += 15
        if not features["trust_signals"]["has_bulk"]:
            integrity_score += 10
        if structural_score > 60:
            integrity_score += 15

        attribution["Integrity"] = min(40, integrity_score)

        # Calculate Stealth score
        stealth_score = 0
        if correlation["is_obfuscated"]:
            stealth_score += 20
        if features["iat_analysis"].get("is_ordinal_heavy", False):
            stealth_score += 15
        if structural_score > 50:
            stealth_score += 15

        attribution["Stealth"] = min(40, stealth_score)

        # Determine primary threat driver
        primary_driver = max(attribution, key=attribution.get)

        return attribution, primary_driver

    def generate_verdict(
        self,
        features: Dict,
        correlation: Dict,
        structural_score: int = 0,
        string_analysis: Optional[StringAnalysisResult] = None,
    ) -> Dict:
        """
        Generate final verdict by combining all phases.

        Args:
            features: From FeatureExtractor
            correlation: From CorrelationEngine
            structural_score: From section analysis
            string_analysis: From StringAnalyzer (NEW)

        Returns:
            Comprehensive threat assessment with attribution
        """
        cfg = self.config.scoring

        # Phase 3a: Indiscrepancy scoring
        indiscrepancy_score, indiscrepancy_reasons = (
            self.indiscrepancy_filter.calculate_indiscrepancy_score(
                features, correlation
            )
        )

        # String analysis score
        string_score = 0
        string_reasons = []
        if string_analysis:
            string_score = min(40, string_analysis.suspicious_score)
            string_reasons = string_analysis.warnings

        # Calculate base threat score
        base_score = (
            correlation["total_capability_score"]
            + indiscrepancy_score
            + int(string_score * 0.5)  # Weight string score at 50%
        )

        # Phase 3b: Trust reduction
        final_score, trust_note, trust_multiplier = (
            self.indiscrepancy_filter.apply_trust_reduction(base_score, features)
        )

        # Cap at 100
        final_score = min(cfg.max_total_score, final_score)

        # Get attribution
        attribution, primary_driver = self.get_score_attribution(
            features, correlation, indiscrepancy_score, structural_score, string_score
        )

        # Determine threat level
        if final_score >= cfg.critical_threshold:
            threat_level = "CRITICAL"
        elif final_score >= cfg.high_threshold:
            threat_level = "HIGH"
        elif final_score >= cfg.medium_threshold:
            threat_level = "MEDIUM"
        elif final_score >= cfg.low_threshold:
            threat_level = "LOW"
        else:
            threat_level = "CLEAN"

        # Compile verdict reasons
        all_reasons = []

        if correlation["capabilities"]:
            all_reasons.append(
                f"Detected {len(correlation['capabilities'])} dangerous capability pattern(s):"
            )
            for cap in correlation["capabilities"]:
                obf_note = (
                    f" (×{cap['obfuscation_multiplier']:.1f} obfuscation)"
                    if cap["is_obfuscated"]
                    else ""
                )
                conf_note = f" [{cap['confidence']*100:.0f}% confidence]"
                all_reasons.append(
                    f"  • {cap['description']}: {cap['final_score']} pts{obf_note}{conf_note}"
                )

        if correlation["is_obfuscated"]:
            all_reasons.append(
                f"Code obfuscation detected (×{correlation['obfuscation_multiplier']:.1f} multiplier):"
            )
            for reason in correlation["obfuscation_reasons"]:
                all_reasons.append(f"  • {reason}")

        if indiscrepancy_reasons:
            all_reasons.append("Behavioral contradictions (indiscrepancy indicators):")
            for reason in indiscrepancy_reasons:
                all_reasons.append(f"  • {reason}")

        if string_reasons:
            all_reasons.append("Suspicious string patterns:")
            for reason in string_reasons:
                all_reasons.append(f"  • {reason}")

        if trust_multiplier < 1.0:
            all_reasons.append(f"Trust signal: {trust_note}")

        # Generate recommendations
        recommendations = self._generate_recommendations(
            threat_level, features, correlation, string_analysis
        )

        return {
            "final_score": final_score,
            "base_score": base_score,
            "threat_level": threat_level,
            "reasons": all_reasons,
            "correlation": correlation,
            "indiscrepancy_score": indiscrepancy_score,
            "string_score": string_score,
            "is_likely_malicious": final_score >= cfg.high_threshold,
            "attribution": attribution,
            "primary_driver": primary_driver,
            "trust_multiplier": trust_multiplier,
            "recommendations": recommendations,
            "capability_summary": correlation.get("capability_summary", {}),
        }

    def _generate_recommendations(
        self,
        threat_level: str,
        features: Dict,
        correlation: Dict,
        string_analysis: Optional[StringAnalysisResult],
    ) -> List[str]:
        """Generate actionable recommendations based on findings"""
        recommendations = []

        if threat_level == "CRITICAL":
            recommendations.append("🔴 IMMEDIATE ISOLATION required")
            recommendations.append("🔴 Analyze in controlled sandbox environment")
            recommendations.append("🔴 Report to security team immediately")
            recommendations.append(
                "🔴 Check for indicators of compromise (IOCs) on network"
            )
        elif threat_level == "HIGH":
            recommendations.append("🟠 DO NOT EXECUTE on production systems")
            recommendations.append("🟠 Perform detailed sandbox analysis")
            recommendations.append("🟠 Review with security team before any action")
        elif threat_level == "MEDIUM":
            recommendations.append("🟡 Exercise caution before execution")
            recommendations.append("🟡 Review manually for false positives")
            recommendations.append("🟡 Monitor closely if executed")
        elif threat_level == "LOW":
            recommendations.append("🟢 Appears relatively safe")
            recommendations.append("🟢 Standard security precautions apply")
        else:
            recommendations.append("✅ File appears legitimate")
            recommendations.append("✅ No significant threats detected")

        # Specific recommendations based on findings
        cap_summary = correlation.get("capability_summary", {})

        if "ransomware" in cap_summary.get("threat_categories", []):
            recommendations.append(
                "⚠️ RANSOMWARE INDICATORS: Ensure backups are current and isolated"
            )

        if "credential_theft" in cap_summary.get("threat_categories", []):
            recommendations.append(
                "⚠️ CREDENTIAL THEFT: Rotate passwords if file was executed"
            )

        if string_analysis and string_analysis.urls:
            recommendations.append(
                f"⚠️ Network IOCs: {len(string_analysis.urls)} URLs found - check firewall logs"
            )

        if string_analysis and string_analysis.ip_addresses:
            external_ips = [
                ip
                for ip in string_analysis.ip_addresses
                if not ip.startswith(("10.", "192.168.", "172.16.", "127.", "0."))
            ]
            if external_ips:
                recommendations.append(
                    f"⚠️ Network IOCs: {len(external_ips)} external IPs found"
                )

        return recommendations
