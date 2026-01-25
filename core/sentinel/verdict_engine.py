"""
Phase 3: Indiscrepancy Filter & Final Verdict
Detects contradictions and applies trust reduction
"""

from typing import Dict, Tuple, List


class IndiscrepancyFilter:
    """Detect contradictions that indicate malicious intent"""

    @staticmethod
    def calculate_indiscrepancy_score(
        features: Dict, correlation: Dict
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
        if iat["total_imports"] <= 5 and iat.get("has_critical_loaders", False):
            score += 20
            reasons.append(
                f"MINIMAL IMPORTS: Only {iat['total_imports']} imports with manual loaders (hiding behavior)"
            )

        # ======================================
        # Check 4: Ordinal Hiding
        # ======================================
        if iat["ordinal_ratio"] > 0.3:  # >30% imports by ordinal
            score += 15
            reasons.append(
                f"ORDINAL HIDING: {iat['ordinal_ratio']*100:.0f}% of imports by ordinal (evading string detection)"
            )

        # ======================================
        # Check 5: No Imports at All
        # ======================================
        if not iat["has_imports"]:
            score += 25
            reasons.append(
                "NO IMPORTS: Binary has no import table (packed or self-contained)"
            )

        return score, reasons

    @staticmethod
    def apply_trust_reduction(base_score: int, features: Dict) -> Tuple[int, str]:
        """
        Apply trust-based score reduction.

        Rule: If digitally signed, reduce score by 80% (trust but verify)
        """
        trust_signals = features["trust_signals"]

        if trust_signals["has_signature"]:
            reduced_score = int(base_score * 0.2)  # 80% reduction
            reason = f"Score reduced from {base_score} to {reduced_score} due to valid digital signature"
            return reduced_score, reason

        return base_score, "No trust reduction applied (unsigned binary)"


class VerdictEngine:
    """Final verdict generator with threat attribution"""

    @staticmethod
    def get_score_attribution(
        features: Dict,
        correlation: Dict,
        indiscrepancy_score: int,
        structural_score: int,
    ) -> Tuple[Dict, str]:
        """
        Calculate threat score attribution across four pillars.

        Returns:
            (attribution_dict, primary_driver)
        """
        # Map scores to threat pillars
        attribution = {
            "Capabilities": min(50, correlation["total_capability_score"]),  # Cap at 50
            "Stealth": min(
                40, int(correlation["obfuscation_multiplier"] * 15)
            ),  # Obfuscation + structural
            "Integrity": 0,  # Will calculate below
            "Intent": min(30, indiscrepancy_score),  # Behavioral contradictions
        }

        # Calculate Integrity score (trust deficit)
        integrity_score = 0
        if not features["trust_signals"]["has_signature"]:
            integrity_score += 15
        if not features["trust_signals"]["has_bulk"]:
            integrity_score += 10
        if structural_score > 60:  # High structural anomaly
            integrity_score += 15

        attribution["Integrity"] = min(40, integrity_score)

        # Calculate Stealth more accurately
        stealth_score = 0
        if correlation["is_obfuscated"]:
            stealth_score += 20
        if features["iat_analysis"]["ordinal_ratio"] > 0.3:
            stealth_score += 15
        if structural_score > 50:
            stealth_score += 15

        attribution["Stealth"] = min(40, stealth_score)

        # Determine primary threat driver
        primary_driver = max(attribution, key=attribution.get)

        return attribution, primary_driver

    @staticmethod
    def generate_verdict(
        features: Dict, correlation: Dict, structural_score: int = 0
    ) -> Dict:
        """
        Generate final verdict by combining all phases.

        Args:
            features: From FeatureExtractor
            correlation: From CorrelationEngine
            structural_score: From section analysis

        Returns:
            Comprehensive threat assessment with attribution
        """
        # Phase 3a: Indiscrepancy scoring
        indiscrepancy_score, indiscrepancy_reasons = (
            IndiscrepancyFilter.calculate_indiscrepancy_score(features, correlation)
        )

        # Calculate base threat score
        base_score = correlation["total_capability_score"] + indiscrepancy_score

        # Phase 3b: Trust reduction
        final_score, trust_note = IndiscrepancyFilter.apply_trust_reduction(
            base_score, features
        )

        # Cap at 100
        final_score = min(100, final_score)

        # Get attribution
        attribution, primary_driver = VerdictEngine.get_score_attribution(
            features, correlation, indiscrepancy_score, structural_score
        )

        # Determine threat level
        if final_score >= 80:
            threat_level = "CRITICAL"
        elif final_score >= 60:
            threat_level = "HIGH"
        elif final_score >= 40:
            threat_level = "MEDIUM"
        elif final_score >= 20:
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
                all_reasons.append(
                    f"  • {cap['description']}: {cap['final_score']} pts{obf_note}"
                )

        if correlation["is_obfuscated"]:
            all_reasons.append(
                f"Code obfuscation detected (×{correlation['obfuscation_multiplier']:.1f} multiplier):"
            )
            for reason in correlation["obfuscation_reasons"]:
                all_reasons.append(f"  • {reason}")

        if indiscrepancy_reasons:
            all_reasons.append("Indiscrepancy indicators:")
            for reason in indiscrepancy_reasons:
                all_reasons.append(f"  • {reason}")

        if features["trust_signals"]["has_signature"]:
            all_reasons.append(f"Trust signal: {trust_note}")

        return {
            "final_score": final_score,
            "base_score": base_score,
            "threat_level": threat_level,
            "reasons": all_reasons,
            "correlation": correlation,
            "indiscrepancy_score": indiscrepancy_score,
            "is_likely_malicious": final_score >= 60,
            "attribution": attribution,
            "primary_driver": primary_driver,
        }
