"""Qualys AI Analyst Copilot — main entry point.

Enterprise pipeline:
  1. Parse Qualys CSV export
  2. Compute statistics & day-over-day delta
  3. Display terminal dashboard
  4. Invoke Amazon Bedrock (Claude 3.5 Sonnet) for AI analysis
  5. Generate multi-format executive reports (HTML, Markdown, PDF)
"""

import logging
import os
import sys
from pathlib import Path

# Fix Windows console encoding
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from config import Config
from src.analyzer import VulnerabilityAnalyzer
from src.bedrock_client import BedrockClient
from src.dashboard import Dashboard
from src.delta_engine import DeltaEngine
from src.parser import QualysParser
from src.report_generator import ReportGenerator


def configure_logging() -> None:
    """Configure application-wide logging."""
    logging.basicConfig(
        level=getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("qualys_copilot.log", encoding="utf-8"),
        ],
    )


def main() -> None:
    """Run the Qualys AI Analyst Copilot pipeline."""
    configure_logging()
    logger = logging.getLogger(__name__)
    logger.info("=" * 60)
    logger.info("Qualys AI Analyst Copilot - Starting pipeline")
    logger.info("LLM Provider: Amazon Bedrock (%s)", Config.BEDROCK_MODEL_ID)
    logger.info("=" * 60)

    # Step 1: Parse CSV
    logger.info("Step 1/5: Parsing Qualys CSV export")
    parser = QualysParser()
    df = parser.get_dataframe()

    # Step 2: Analyze + Delta
    logger.info("Step 2/5: Analyzing vulnerability data")
    analyzer = VulnerabilityAnalyzer(df)
    stats = analyzer.compute_statistics()

    # Delta comparison (day-over-day)
    delta_engine = DeltaEngine()
    delta_engine.rotate_snapshots()
    delta_engine.save_snapshot(df, label="today")
    yesterday_data = delta_engine.get_yesterday_snapshot()

    delta_summary = ""
    if yesterday_data:
        logger.info("Yesterday snapshot found - computing delta")
        today_snapshot = delta_engine.load_snapshot(Config.BASE_DIR / "data" / "snapshot_today.json")
        bedrock = BedrockClient()
        delta_result = bedrock.compute_delta(yesterday_data, today_snapshot)
        delta_summary = delta_result.to_summary()
        print(f"\n   Delta: +{len(delta_result.new_vulnerabilities)} new, "
              f"-{len(delta_result.resolved_vulnerabilities)} resolved, "
              f"{len(delta_result.new_critical_risks)} new critical risks")
    else:
        logger.info("No previous snapshot - first run, skipping delta")
        print("\n   [First run] No previous snapshot for delta comparison.")

    # Step 3: Display dashboard
    logger.info("Step 3/5: Displaying dashboard")
    dashboard = Dashboard(stats)
    dashboard.display()

    # Step 4: AI Analysis via Amazon Bedrock
    logger.info("Step 4/5: Generating AI analysis via Amazon Bedrock (Claude 3.5 Sonnet)")
    if not yesterday_data:
        bedrock = BedrockClient()

    findings_text = analyzer.prepare_findings_for_ai()
    stats_text = stats.to_summary_text()
    if delta_summary:
        stats_text += "\n\n" + delta_summary

    print("\n   Sending findings to Amazon Bedrock (Claude 3.5 Sonnet)...")
    ai_analysis = bedrock.analyze_vulnerabilities(findings_text)
    logger.info("AI vulnerability analysis complete")

    # Delta-specific analysis if available
    if yesterday_data and delta_result.new_vulnerabilities:
        print("   Analyzing day-over-day delta...")
        delta_ai = bedrock.analyze_delta(delta_result)
        ai_analysis += "\n\n---\n\n## Day-over-Day Trend Analysis\n\n" + delta_ai

    print("   Generating executive report...")
    executive_report = bedrock.generate_executive_report(stats_text, ai_analysis)
    logger.info("AI executive report generation complete")

    # Step 5: Generate reports
    logger.info("Step 5/5: Generating reports")
    report_gen = ReportGenerator()
    outputs = report_gen.generate_all(executive_report, stats)

    logger.info("Reports generated successfully:")
    for fmt, path in outputs.items():
        logger.info("  %s: %s", fmt.upper(), path)

    print("\n[SUCCESS] All reports generated:")
    for fmt, path in outputs.items():
        print(f"   {fmt.upper()}: {path}")
    print()


if __name__ == "__main__":
    main()
