"""
PDF Report Generator for PE-Sentinel
Generates professional PDF reports with threat analysis results
All style names prefixed with PS_ to avoid conflicts with built-in styles
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
    print("[WARN] reportlab not installed. PDF export disabled.")


class PDFReportGenerator:
    """Generate PDF reports for PE analysis"""

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
        """Setup custom paragraph styles with unique prefixed names"""
        # All names prefixed with PS_ (PE-Sentinel) to avoid any conflicts

        self.styles.add(
            ParagraphStyle(
                name="PS_Title",
                parent=self.styles["Heading1"],
                fontSize=24,
                textColor=self.COLORS["primary"],
                spaceAfter=20,
                alignment=TA_CENTER,
            )
        )

        self.styles.add(
            ParagraphStyle(
                name="PS_Section",
                parent=self.styles["Heading2"],
                fontSize=14,
                textColor=self.COLORS["dark"],
                spaceBefore=20,
                spaceAfter=10,
            )
        )

        self.styles.add(
            ParagraphStyle(
                name="PS_SubSection",
                parent=self.styles["Heading3"],
                fontSize=11,
                textColor=self.COLORS["muted"],
                spaceBefore=10,
                spaceAfter=5,
            )
        )

        self.styles.add(
            ParagraphStyle(
                name="PS_Body",
                parent=self.styles["Normal"],
                fontSize=10,
                textColor=self.COLORS["dark"],
                spaceAfter=6,
            )
        )

        self.styles.add(
            ParagraphStyle(
                name="PS_Warning",
                parent=self.styles["Normal"],
                fontSize=10,
                textColor=self.COLORS["danger"],
                leftIndent=20,
                spaceAfter=3,
            )
        )

        self.styles.add(
            ParagraphStyle(
                name="PS_Code",
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
                name="PS_Footer",
                parent=self.styles["Normal"],
                fontSize=8,
                textColor=self.COLORS["muted"],
                alignment=TA_CENTER,
            )
        )

        self.styles.add(
            ParagraphStyle(
                name="PS_CenterMuted",
                parent=self.styles["Normal"],
                fontSize=10,
                textColor=self.COLORS["muted"],
                alignment=TA_CENTER,
            )
        )

        self.styles.add(
            ParagraphStyle(
                name="PS_Malicious",
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
                name="PS_Benign",
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
        """Generate PDF report"""
        buffer = io.BytesIO()

        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=50,
            leftMargin=50,
            topMargin=50,
            bottomMargin=50,
        )

        story = []

        # Title
        story.append(Paragraph("PE-SENTINEL", self.styles["PS_Title"]))
        story.append(Paragraph("Malware Analysis Report", self.styles["PS_SubSection"]))
        story.append(Spacer(1, 20))

        # Sections
        story.extend(self._build_metadata_section())
        story.extend(self._build_threat_section())
        story.extend(self._build_summary_section())
        story.extend(self._build_sections_section())
        story.extend(self._build_imports_section())
        story.extend(self._build_capabilities_section())
        story.extend(self._build_mitre_section())
        story.extend(self._build_iocs_section())
        story.extend(self._build_recommendations_section())

        # Footer
        story.append(Spacer(1, 30))
        story.append(HRFlowable(width="100%", color=self.COLORS["muted"]))
        story.append(
            Paragraph(
                f"Generated by PE-Sentinel • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                self.styles["PS_Footer"],
            )
        )

        doc.build(story)

        pdf_bytes = buffer.getvalue()
        buffer.close()

        if output_path:
            with open(output_path, "wb") as f:
                f.write(pdf_bytes)

        return pdf_bytes

    def _build_metadata_section(self) -> List:
        elements = []
        metadata = self.data.get("metadata", {})

        file_data = [
            ["Filename", str(metadata.get("filename", "Unknown"))],
            ["Architecture", str(metadata.get("architecture", "Unknown"))],
            ["Size", f"{metadata.get('filesize', 0):,} bytes"],
            ["Entry Point", str(metadata.get("entry_point", "Unknown"))],
            ["Signed", "Yes" if metadata.get("is_signed") else "No"],
            ["Analysis Time", str(self.data.get("timestamp", ""))[:19]],
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
        elements = []
        scores = self.data.get("scores", {})
        threat_level = str(scores.get("threat_level", "UNKNOWN"))
        threat_color = self.THREAT_COLORS.get(threat_level, self.COLORS["muted"])

        elements.append(Paragraph("THREAT ASSESSMENT", self.styles["PS_Section"]))

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
        elements.append(Spacer(1, 10))

        # Threat level text - create inline style to avoid conflicts
        elements.append(
            Paragraph(
                f"<font color='#{threat_color.hexval()[2:]}'><b>Threat Level: {threat_level}</b></font>",
                ParagraphStyle(
                    "PS_ThreatInline",
                    parent=self.styles["Normal"],
                    fontSize=14,
                    alignment=TA_CENTER,
                ),
            )
        )

        if scores.get("primary_driver"):
            elements.append(
                Paragraph(
                    f"Primary Driver: {scores.get('primary_driver')}",
                    self.styles["PS_CenterMuted"],
                )
            )

        elements.append(Spacer(1, 20))
        return elements

    def _build_summary_section(self) -> List:
        elements = []
        verdict = self.data.get("verdict", {})

        elements.append(Paragraph("EXECUTIVE SUMMARY", self.styles["PS_Section"]))

        if verdict.get("is_likely_malicious"):
            elements.append(
                Paragraph(
                    "This file exhibits characteristics consistent with MALICIOUS software.",
                    self.styles["PS_Malicious"],
                )
            )
        else:
            elements.append(
                Paragraph(
                    "This file appears to be BENIGN based on static analysis.",
                    self.styles["PS_Benign"],
                )
            )

        reasons = verdict.get("reasons", [])
        if reasons:
            elements.append(Spacer(1, 10))
            elements.append(Paragraph("Key Findings:", self.styles["PS_SubSection"]))
            for reason in reasons[:10]:
                elements.append(Paragraph(f"• {str(reason)}", self.styles["PS_Body"]))

        elements.append(Spacer(1, 10))
        return elements

    def _build_sections_section(self) -> List:
        elements = []
        sections = self.data.get("sections", [])
        if not sections:
            return elements

        elements.append(Paragraph("SECTION ANALYSIS", self.styles["PS_Section"]))

        table_data = [["Section", "Entropy", "Ratio", "Perms", "Score", "Level"]]
        for section in sections:
            table_data.append(
                [
                    str(section.get("name", "?"))[:12],
                    f"{section.get('entropy', 0):.2f}",
                    f"{section.get('size_ratio', 0):.2f}x",
                    str(section.get("permissions", ""))[:5],
                    str(section.get("suspicion_score", 0)),
                    str(section.get("suspicion_level", "?"))[:8],
                ]
            )

        table = Table(table_data, colWidths=[80, 60, 60, 50, 50, 70])
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

        for i, section in enumerate(sections, 1):
            level = str(section.get("suspicion_level", ""))
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
        elements = []
        import_analysis = self.data.get("import_analysis", {})

        if not import_analysis or import_analysis.get("error"):
            return elements

        elements.append(Paragraph("IMPORT ANALYSIS", self.styles["PS_Section"]))

        density = import_analysis.get("density", {})
        ordinal = import_analysis.get("ordinal", {})
        runtime = import_analysis.get("runtime", {})

        import_data = [
            ["Total Imports", str(density.get("total_imports", 0))],
            ["DLL Count", str(density.get("dll_count", 0))],
            ["Density Level", str(density.get("level", "N/A"))],
            ["Runtime Detected", str(runtime.get("detected", "Unknown"))],
            ["Ordinal Ratio", str(ordinal.get("ratio_percent", "0%"))],
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
        elements.append(Spacer(1, 15))
        return elements

    def _build_capabilities_section(self) -> List:
        elements = []
        capabilities = self.data.get("capabilities", [])
        if not capabilities:
            return elements

        elements.append(Paragraph("DETECTED CAPABILITIES", self.styles["PS_Section"]))

        for cap in capabilities:
            elements.append(
                Paragraph(
                    f"<b>{cap.get('description', 'Unknown')}</b> (Score: {cap.get('score', 0)})",
                    self.styles["PS_Body"],
                )
            )
            apis = cap.get("matched_apis", [])
            if apis:
                api_str = ", ".join(str(a) for a in apis[:5])
                if len(apis) > 5:
                    api_str += "..."
                elements.append(Paragraph(f"APIs: {api_str}", self.styles["PS_Code"]))

        elements.append(Spacer(1, 15))
        return elements

    def _build_mitre_section(self) -> List:
        elements = []
        mitre = self.data.get("mitre", {})
        techniques = mitre.get("techniques", [])

        if not techniques:
            return elements

        elements.append(Paragraph("MITRE ATT&CK MAPPING", self.styles["PS_Section"]))

        table_data = [["Technique", "Name", "Tactic", "Confidence"]]
        for tech in techniques[:15]:
            table_data.append(
                [
                    str(tech.get("id", ""))[:10],
                    str(tech.get("name", ""))[:25],
                    str(tech.get("tactic", ""))[:20],
                    str(tech.get("confidence", ""))[:10],
                ]
            )

        table = Table(table_data, colWidths=[70, 150, 120, 70])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), self.COLORS["danger"]),
                    ("TEXTCOLOR", (0, 0), (-1, 0), self.COLORS["white"]),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("PADDING", (0, 0), (-1, -1), 5),
                    ("GRID", (0, 0), (-1, -1), 0.5, self.COLORS["light"]),
                ]
            )
        )

        elements.append(table)
        elements.append(Spacer(1, 15))
        return elements

    def _build_iocs_section(self) -> List:
        elements = []
        strings = self.data.get("strings", {})

        urls = strings.get("urls", [])
        ips = strings.get("ip_addresses", [])

        if not urls and not ips:
            return elements

        elements.append(
            Paragraph("INDICATORS OF COMPROMISE", self.styles["PS_Section"])
        )

        if urls:
            elements.append(Paragraph("URLs:", self.styles["PS_SubSection"]))
            for url in urls[:8]:
                elements.append(Paragraph(str(url)[:70], self.styles["PS_Code"]))
            if len(urls) > 8:
                elements.append(
                    Paragraph(f"... and {len(urls) - 8} more", self.styles["PS_Body"])
                )

        if ips:
            elements.append(Paragraph("IP Addresses:", self.styles["PS_SubSection"]))
            ip_str = ", ".join(str(ip) for ip in ips[:15])
            elements.append(Paragraph(ip_str, self.styles["PS_Code"]))

        elements.append(Spacer(1, 15))
        return elements

    def _build_recommendations_section(self) -> List:
        elements = []
        verdict = self.data.get("verdict", {})
        recommendations = verdict.get("recommendations", [])

        if not recommendations:
            return elements

        elements.append(Paragraph("RECOMMENDATIONS", self.styles["PS_Section"]))
        for rec in recommendations[:8]:
            elements.append(Paragraph(f"• {str(rec)}", self.styles["PS_Body"]))

        return elements


def generate_pdf_report(analysis_data: Dict, output_path: str = None) -> bytes:
    """Generate PDF report from analysis data"""
    if not REPORTLAB_AVAILABLE:
        raise ImportError("reportlab is required. Install with: pip install reportlab")

    generator = PDFReportGenerator(analysis_data)
    return generator.generate(output_path)
