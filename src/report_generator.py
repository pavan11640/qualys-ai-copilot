"""Report generator — produces HTML, Markdown, and PDF outputs."""

import logging
from datetime import datetime
from pathlib import Path

import markdown as md
from fpdf import FPDF
from jinja2 import Environment, FileSystemLoader

from config import Config
from src.analyzer import VulnerabilityStats

logger = logging.getLogger(__name__)


class ReportPDF(FPDF):
    """Custom PDF class with header/footer."""

    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(100, 100, 100)
        self.cell(0, 8, "Qualys AI Analyst Copilot - Vulnerability Assessment Report", align="C")
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")


class ReportGenerator:
    """Generates vulnerability assessment reports in multiple formats."""

    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Config.OUTPUT_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def generate_markdown(self, ai_report: str, stats: VulnerabilityStats) -> Path:
        """Generate a Markdown report file."""
        logger.info("Generating Markdown report")
        content = self._build_markdown(ai_report, stats)
        output_path = self.output_dir / f"vulnerability_report_{self.timestamp}.md"
        output_path.write_text(content, encoding="utf-8")
        logger.info("Markdown report saved: %s", output_path)
        return output_path

    def generate_html(self, ai_report: str, stats: VulnerabilityStats) -> Path:
        """Generate an HTML report file using Jinja2 template."""
        logger.info("Generating HTML report")
        markdown_content = self._build_markdown(ai_report, stats)
        html_body = md.markdown(markdown_content, extensions=["tables", "fenced_code"])

        env = Environment(loader=FileSystemLoader(str(Config.TEMPLATES_DIR)))
        template = env.get_template("report.html")
        html_output = template.render(
            title="Qualys AI Analyst Copilot - Vulnerability Assessment Report",
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            stats=stats.to_dict(),
            body=html_body,
        )

        output_path = self.output_dir / f"vulnerability_report_{self.timestamp}.html"
        output_path.write_text(html_output, encoding="utf-8")
        logger.info("HTML report saved: %s", output_path)
        return output_path

    def generate_pdf(self, ai_report: str, stats: VulnerabilityStats) -> Path:
        """Generate a PDF report file using fpdf2."""
        logger.info("Generating PDF report")
        output_path = self.output_dir / f"vulnerability_report_{self.timestamp}.pdf"

        pdf = ReportPDF()
        pdf.alias_nb_pages()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=20)

        # Title
        pdf.set_font("Helvetica", "B", 18)
        pdf.set_text_color(44, 62, 80)
        pdf.cell(0, 12, "Vulnerability Assessment Report", ln=True, align="C")
        pdf.ln(4)

        # Timestamp
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 8, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        pdf.ln(8)

        # Statistics table
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(44, 62, 80)
        pdf.cell(0, 10, "Vulnerability Statistics", ln=True)
        pdf.ln(2)

        stats_rows = [
            ("Total Vulnerabilities", str(stats.total)),
            ("Critical", str(stats.critical)),
            ("High", str(stats.high)),
            ("Medium", str(stats.medium)),
            ("Low", str(stats.low)),
            ("Informational", str(stats.informational)),
        ]

        pdf.set_font("Helvetica", "B", 10)
        pdf.set_fill_color(44, 62, 80)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(95, 8, "Metric", border=1, fill=True)
        pdf.cell(45, 8, "Count", border=1, fill=True, ln=True)

        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(0, 0, 0)
        for i, (metric, value) in enumerate(stats_rows):
            if i % 2 == 0:
                pdf.set_fill_color(236, 240, 241)
            else:
                pdf.set_fill_color(255, 255, 255)
            pdf.cell(95, 7, metric, border=1, fill=True)
            pdf.cell(45, 7, value, border=1, fill=True, ln=True)

        pdf.ln(10)

        # AI Report content
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(44, 62, 80)
        pdf.cell(0, 10, "Executive Analysis", ln=True)
        pdf.ln(2)

        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(0, 0, 0)

        for line in ai_report.split("\n"):
            stripped = line.strip()
            if not stripped:
                pdf.ln(3)
            elif stripped.startswith("###"):
                pdf.set_font("Helvetica", "B", 11)
                pdf.set_text_color(52, 73, 94)
                pdf.multi_cell(0, 6, stripped.lstrip("#").strip())
                pdf.set_font("Helvetica", "", 10)
                pdf.set_text_color(0, 0, 0)
            elif stripped.startswith("##"):
                pdf.set_font("Helvetica", "B", 12)
                pdf.set_text_color(44, 62, 80)
                pdf.multi_cell(0, 7, stripped.lstrip("#").strip())
                pdf.set_font("Helvetica", "", 10)
                pdf.set_text_color(0, 0, 0)
            elif stripped.startswith("#"):
                pdf.set_font("Helvetica", "B", 14)
                pdf.set_text_color(44, 62, 80)
                pdf.multi_cell(0, 8, stripped.lstrip("#").strip())
                pdf.set_font("Helvetica", "", 10)
                pdf.set_text_color(0, 0, 0)
            elif stripped.startswith("- ") or stripped.startswith("* "):
                pdf.cell(5, 6, "")
                pdf.multi_cell(0, 6, f"  {stripped}")
            else:
                pdf.multi_cell(0, 6, stripped)

        pdf.output(str(output_path))
        logger.info("PDF report saved: %s", output_path)
        return output_path

    def generate_all(self, ai_report: str, stats: VulnerabilityStats) -> dict[str, Path]:
        """Generate all report formats."""
        return {
            "markdown": self.generate_markdown(ai_report, stats),
            "html": self.generate_html(ai_report, stats),
            "pdf": self.generate_pdf(ai_report, stats),
        }

    @staticmethod
    def _build_markdown(ai_report: str, stats: VulnerabilityStats) -> str:
        """Build the full markdown report content."""
        header = (
            "# Qualys AI Analyst Copilot - Vulnerability Assessment Report\n\n"
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            "---\n\n"
            "## Vulnerability Statistics\n\n"
            "| Metric | Count |\n"
            "|--------|-------|\n"
            f"| Total Vulnerabilities | {stats.total} |\n"
            f"| Critical | {stats.critical} |\n"
            f"| High | {stats.high} |\n"
            f"| Medium | {stats.medium} |\n"
            f"| Low | {stats.low} |\n"
            f"| Informational | {stats.informational} |\n\n"
            "---\n\n"
        )
        return header + ai_report
