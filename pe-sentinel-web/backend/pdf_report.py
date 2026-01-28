"""
PDF Report Generator for PE-Sentinel
Generates professional PDF reports with threat analysis results
"""

import io
from datetime import datetime
from typing import Dict, List, Optional

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, mm
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        PageBreak,
        Image,
        HRFlowable,
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print(
        "[WARN] reportlab not installed. PDF export disabled. Install with: pip install reportlab"
    )


class PDFReportGenerator:
    """Generate PDF reports for PE analysis"""

    # Color scheme
    COLORS = {
        "primary": colors.HexColor("#4f46e5"),
        "danger": colors.HexColor("#dc3545"),
        "warning": colors.HexColor("#ffc107"),
        "success": colors.HexColor("#28a745"),
        "info": colors.HexColor("#17a2b8"),
        "dark": colors.HexColor("#1e293b"),
        "muted": colors.HexColor("#64748b"),
        "light": colors.HexColor("#f8fafc"),
        "white": colors.white,
    }

    THREAT_COLORS = {
        "CRITICAL": colors.HexColor("#dc3545"),
        "HIGH": colors.HexColor("#fd7e14"),
        "MEDIUM": colors.HexColor("#ffc107"),
        "LOW": colors.HexColor("#28a745"),
        "CLEAN": colors.HexColor("#20c997"),
    }

    def __init__(self, analysis_data: Dict):
        if not REPORTLAB_AVAILABLE:
            raise ImportError("reportlab is required for PDF generation")
        self.data = analysis_data
        self.styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self):
        """Setup custom paragraph styles with unique names"""
        # Use unique names to avoid conflicts with built-in styles
        self.styles.add(
            ParagraphStyle(
                name="ReportTitle",
                parent=self.styles["Heading1"],
                fontSize=24,
                textColor=self.COLORS["primary"],
                spaceAfter=20,
                alignment=TA_CENTER,
            )
        )

        self.styles.add(
            ParagraphStyle(
                name="SectionHeader",
                parent=self.styles["Heading2"],
                fontSize=14,
                textColor=self.COLORS["dark"],
                spaceBefore=20,
                spaceAfter=10,
                borderWidth=0,
                borderColor=self.COLORS["primary"],
                borderPadding=5,
            )
        )

        self.styles.add(
            ParagraphStyle(
                name="SubHeader",
                parent=self.styles["Heading3"],
                fontSize=11,
                textColor=self.COLORS["muted"],
                spaceBefore=10,
                spaceAfter=5,
            )
        )

        self.styles.add(
            ParagraphStyle(
                name="BodyText",
                parent=self.styles["Normal"],
                fontSize=10,
                textColor=self.COLORS["dark"],
                spaceAfter=6,
            )
        )

        self.styles.add(
            ParagraphStyle(
                name="WarningText",
                parent=self.styles["Normal"],
                fontSize=10,
                textColor=self.COLORS["danger"],
                leftIndent=20,
                spaceAfter=3,
            )
        )

        self.styles.add(
            ParagraphStyle(
                name="CodeText",
                parent=self.styles["Normal"],
                fontSize=9,
                fontName="Courier",
                textColor=self.COLORS["dark"],
                backColor=self.COLORS["light"],
                leftIndent=10,
                rightIndent=10,
                spaceAfter=6,
            )
        )

        self.styles.add(
            ParagraphStyle(
                name="FooterText",
                parent=self.styles["Normal"],
                fontSize=8,
                textColor=self.COLORS["muted"],
                alignment=TA_CENTER,
            )
        )

        self.styles.add(
            ParagraphStyle(
                name="ThreatLevel",
                parent=self.styles["Normal"],
                fontSize=14,
                alignment=TA_CENTER,
            )
        )

        self.styles.add(
            ParagraphStyle(
                name="DriverText",
                parent=self.styles["Normal"],
                fontSize=10,
                textColor=self.COLORS["muted"],
                alignment=TA_CENTER,
            )
        )

        self.styles.add(
            ParagraphStyle(
                name="MaliciousWarning",
                parent=self.styles["Normal"],
                fontSize=11,
                textColor=self.COLORS["danger"],
                backColor=colors.HexColor("#fee2e2"),
                leftIndent=10,
                rightIndent=10,
                spaceBefore=5,
                spaceAfter=5,
            )
        )

        self.styles.add(
            ParagraphStyle(
                name="BenignNote",
                parent=self.styles["Normal"],
                fontSize=11,
                textColor=self.COLORS["success"],
                backColor=colors.HexColor("#dcfce7"),
                leftIndent=10,
                rightIndent=10,
                spaceBefore=5,
                spaceAfter=5,
            )
        )

    def generate(self, output_path: str = None) -> bytes:
        """
        Generate PDF report

        Args:
            output_path: Optional file path to save PDF

        Returns:
            PDF as bytes
        """
        buffer = io.BytesIO()

        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=50,
            leftMargin=50,
            topMargin=50,
            bottomMargin=50,
        )

        # Build story (content)
        story = []

        # Title
        story.append(Paragraph("PE-SENTINEL", self.styles["ReportTitle"]))
        story.append(Paragraph("Malware Analysis Report", self.styles["SubHeader"]))
        story.append(Spacer(1, 20))

        # Metadata bar
        story.extend(self._build_metadata_section())

        # Threat Score
        story.extend(self._build_threat_section())

        # Executive Summary
        story.extend(self._build_summary_section())

        # Section Analysis
        story.extend(self._build_sections_section())

        # Import Analysis
        story.extend(self._build_imports_section())

        # Capabilities
        story.extend(self._build_capabilities_section())

        # MITRE ATT&CK
        story.extend(self._build_mitre_section())

        # Strings/IOCs
        story.extend(self._build_iocs_section())

        # Recommendations
        story.extend(self._build_recommendations_section())

        # Footer
        story.append(Spacer(1, 30))
        story.append(HRFlowable(width="100%", color=self.COLORS["muted"]))
        story.append(
            Paragraph(
                f"Generated by PE-Sentinel • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                self.styles["FooterText"],
            )
        )

        # Build PDF
        doc.build(story)

        pdf_bytes = buffer.getvalue()
        buffer.close()

        # Save to file if path provided
        if output_path:
            with open(output_path, "wb") as f:
                f.write(pdf_bytes)

        return pdf_bytes

    def _build_metadata_section(self) -> List:
        """Build file metadata section"""
        elements = []

        metadata = self.data.get("metadata", {})

        # File info table
        file_data = [
            ["Filename", str(metadata.get("filename", "Unknown"))],
            ["Architecture", str(metadata.get("architecture", "Unknown"))],
            ["Size", f"{metadata.get('filesize', 0):,} bytes"],
            ["Entry Point", str(metadata.get("entry_point", "Unknown"))],
            ["Signed", "Yes ✓" if metadata.get("is_signed") else "No ✗"],
            [
                "Analysis Time",
                str(self.data.get("timestamp", datetime.now().isoformat())),
            ],
        ]

        table = Table(file_data, colWidths=[120, 350])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), self.COLORS["light"]),
                    ("TEXTCOLOR", (0, 0), (0, -1), self.COLORS["muted"]),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("ALIGN", (0, 0), (0, -1), "RIGHT"),
                    ("ALIGN", (1, 0), (1, -1), "LEFT"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("PADDING", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, self.COLORS["light"]),
                ]
            )
        )

        elements.append(table)
        elements.append(Spacer(1, 20))

        return elements

    def _build_threat_section(self) -> List:
        """Build threat score section"""
        elements = []

        scores = self.data.get("scores", {})
        threat_level = scores.get("threat_level", "UNKNOWN")
        threat_color = self.THREAT_COLORS.get(threat_level, self.COLORS["muted"])

        elements.append(Paragraph("THREAT ASSESSMENT", self.styles["SectionHeader"]))

        # Score cards
        score_data = [
            ["Structural", "Behavioral", "Overall"],
            [
                str(scores.get("structural", 0)),
                str(scores.get("behavioral", 0)),
                str(scores.get("overall", 0)),
            ],
        ]

        score_table = Table(score_data, colWidths=[150, 150, 150])
        score_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), self.COLORS["dark"]),
                    ("TEXTCOLOR", (0, 0), (-1, 0), self.COLORS["white"]),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 1), (-1, 1), 24),
                    ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("PADDING", (0, 0), (-1, -1), 12),
                    ("BACKGROUND", (2, 1), (2, 1), threat_color),
                    ("TEXTCOLOR", (2, 1), (2, 1), self.COLORS["white"]),
                    ("GRID", (0, 0), (-1, -1), 1, self.COLORS["light"]),
                ]
            )
        )

        elements.append(score_table)

        # Threat level badge
        elements.append(Spacer(1, 10))
        threat_style = ParagraphStyle(
            "ThreatLevelDynamic",
            parent=self.styles["Normal"],
            fontSize=14,
            textColor=threat_color,
            alignment=TA_CENTER,
        )
        elements.append(Paragraph(f"<b>Threat Level: {threat_level}</b>", threat_style))

        # Primary driver
        if scores.get("primary_driver"):
            elements.append(
                Paragraph(
                    f"Primary Threat Driver: {scores.get('primary_driver')}",
                    self.styles["DriverText"],
                )
            )

        elements.append(Spacer(1, 20))

        return elements

    def _build_summary_section(self) -> List:
        """Build executive summary"""
        elements = []

        verdict = self.data.get("verdict", {})

        elements.append(Paragraph("EXECUTIVE SUMMARY", self.styles["SectionHeader"]))

        if verdict.get("is_likely_malicious"):
            elements.append(
                Paragraph(
                    "⚠ This file exhibits characteristics consistent with MALICIOUS software.",
                    self.styles["MaliciousWarning"],
                )
            )
        else:
            elements.append(
                Paragraph(
                    "✓ This file appears to be BENIGN based on static analysis.",
                    self.styles["BenignNote"],
                )
            )

        # Key findings
        reasons = verdict.get("reasons", [])
        if reasons:
            elements.append(Spacer(1, 10))
            elements.append(Paragraph("Key Findings:", self.styles["SubHeader"]))
            for reason in reasons[:10]:  # Limit to 10
                elements.append(Paragraph(f"• {str(reason)}", self.styles["BodyText"]))

        elements.append(Spacer(1, 10))

        return elements

    def _build_sections_section(self) -> List:
        """Build section analysis"""
        elements = []

        sections = self.data.get("sections", [])
        if not sections:
            return elements

        elements.append(Paragraph("SECTION ANALYSIS", self.styles["SectionHeader"]))

        # Section table
        table_data = [["Section", "Entropy", "Ratio", "Perms", "Score", "Level"]]

        for section in sections:
            table_data.append(
                [
                    str(section.get("name", "Unknown")),
                    f"{section.get('entropy', 0):.2f}",
                    f"{section.get('size_ratio', 0):.2f}x",
                    str(section.get("permissions", "")),
                    str(section.get("suspicion_score", 0)),
                    str(section.get("suspicion_level", "UNKNOWN")),
                ]
            )

        table = Table(table_data, colWidths=[80, 60, 60, 60, 50, 80])

        # Style the table
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), self.COLORS["dark"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), self.COLORS["white"]),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("PADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, self.COLORS["light"]),
        ]

        # Color code suspicious sections
        for i, section in enumerate(sections, 1):
            level = section.get("suspicion_level", "")
            if level == "CRITICAL":
                style.append(
                    ("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fee2e2"))
                )
            elif level == "HIGH":
                style.append(
                    ("BACKGROUND", (0, i), (-1, i), colors.HexColor("#ffedd5"))
                )

        table.setStyle(TableStyle(style))
        elements.append(table)
        elements.append(Spacer(1, 15))

        return elements

    def _build_imports_section(self) -> List:
        """Build import analysis section"""
        elements = []

        features = self.data.get("features", {})
        iat = features.get("iat_analysis", {})

        if not iat:
            return elements

        elements.append(Paragraph("IMPORT ANALYSIS", self.styles["SectionHeader"]))

        # Import stats
        import_data = [
            ["Total Imports", str(iat.get("total_imports", 0))],
            ["DLL Count", str(iat.get("dll_count", 0))],
            ["Ordinal Imports", str(iat.get("ordinal_count", 0))],
            ["Ordinal Ratio", f"{iat.get('ordinal_ratio', 0) * 100:.1f}%"],
            ["Manual Loaders", "Yes ⚠" if iat.get("has_critical_loaders") else "No"],
            ["Minimal Imports", "Yes ⚠" if iat.get("is_minimal") else "No"],
        ]

        table = Table(import_data, colWidths=[150, 150])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), self.COLORS["light"]),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("ALIGN", (1, 0), (1, -1), "CENTER"),
                    ("PADDING", (0, 0), (-1, -1), 6),
                    ("GRID", (0, 0), (-1, -1), 0.5, self.COLORS["light"]),
                ]
            )
        )

        elements.append(table)

        # Warnings
        if iat.get("is_ordinal_heavy"):
            elements.append(
                Paragraph(
                    "⚠ High ordinal ratio detected - possible API hiding",
                    self.styles["WarningText"],
                )
            )
        if iat.get("is_minimal"):
            elements.append(
                Paragraph(
                    "⚠ Minimal imports - characteristic of packers/loaders",
                    self.styles["WarningText"],
                )
            )

        elements.append(Spacer(1, 15))

        return elements

    def _build_capabilities_section(self) -> List:
        """Build capabilities section"""
        elements = []

        capabilities = self.data.get("capabilities", [])
        if not capabilities:
            return elements

        elements.append(
            Paragraph("DETECTED CAPABILITIES", self.styles["SectionHeader"])
        )

        for cap in capabilities:
            elements.append(
                Paragraph(
                    f"<b>{cap.get('description', 'Unknown')}</b> (Score: {cap.get('score', 0)})",
                    self.styles["BodyText"],
                )
            )

            apis = cap.get("matched_apis", [])
            if apis:
                api_str = ", ".join(str(a) for a in apis[:5])
                if len(apis) > 5:
                    api_str += "..."
                elements.append(Paragraph(f"APIs: {api_str}", self.styles["CodeText"]))

        elements.append(Spacer(1, 15))

        return elements

    def _build_mitre_section(self) -> List:
        """Build MITRE ATT&CK section"""
        elements = []

        mitre = self.data.get("mitre", {})
        techniques = mitre.get("techniques", [])

        if not techniques:
            return elements

        elements.append(Paragraph("MITRE ATT&CK MAPPING", self.styles["SectionHeader"]))

        table_data = [["Technique", "Name", "Tactic", "Confidence"]]

        for tech in techniques:
            table_data.append(
                [
                    str(tech.get("id", "")),
                    str(tech.get("name", "")),
                    str(tech.get("tactic", "")),
                    str(tech.get("confidence", "")),
                ]
            )

        table = Table(table_data, colWidths=[80, 150, 120, 80])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), self.COLORS["danger"]),
                    ("TEXTCOLOR", (0, 0), (-1, 0), self.COLORS["white"]),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("PADDING", (0, 0), (-1, -1), 6),
                    ("GRID", (0, 0), (-1, -1), 0.5, self.COLORS["light"]),
                ]
            )
        )

        elements.append(table)
        elements.append(Spacer(1, 15))

        return elements

    def _build_iocs_section(self) -> List:
        """Build IOCs section"""
        elements = []

        strings = self.data.get("strings", {})

        urls = strings.get("urls", [])
        ips = strings.get("ip_addresses", [])

        if not urls and not ips:
            return elements

        elements.append(
            Paragraph("INDICATORS OF COMPROMISE", self.styles["SectionHeader"])
        )

        if urls:
            elements.append(Paragraph("URLs:", self.styles["SubHeader"]))
            for url in urls[:10]:
                elements.append(Paragraph(str(url)[:80], self.styles["CodeText"]))
            if len(urls) > 10:
                elements.append(
                    Paragraph(f"... and {len(urls) - 10} more", self.styles["BodyText"])
                )

        if ips:
            elements.append(Paragraph("IP Addresses:", self.styles["SubHeader"]))
            ip_str = ", ".join(str(ip) for ip in ips[:20])
            elements.append(Paragraph(ip_str, self.styles["CodeText"]))

        elements.append(Spacer(1, 15))

        return elements

    def _build_recommendations_section(self) -> List:
        """Build recommendations section"""
        elements = []

        verdict = self.data.get("verdict", {})
        recommendations = verdict.get("recommendations", [])

        if not recommendations:
            return elements

        elements.append(Paragraph("RECOMMENDATIONS", self.styles["SectionHeader"]))

        for rec in recommendations:
            elements.append(Paragraph(f"• {str(rec)}", self.styles["BodyText"]))

        return elements


def generate_pdf_report(analysis_data: Dict, output_path: str = None) -> bytes:
    """
    Generate PDF report from analysis data

    Args:
        analysis_data: Complete analysis results dict
        output_path: Optional path to save PDF

    Returns:
        PDF as bytes
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError("reportlab is required. Install with: pip install reportlab")

    generator = PDFReportGenerator(analysis_data)
    return generator.generate(output_path)
