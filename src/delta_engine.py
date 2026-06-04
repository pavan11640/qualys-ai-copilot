"""Day-over-day delta comparison engine for vulnerability data.

Reads yesterday's and today's scan data (JSON format), computes differences,
and prepares structured input for AI analysis via Amazon Bedrock.
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import pandas as pd

from config import Config

logger = logging.getLogger(__name__)


class DeltaEngine:
    """Computes day-over-day vulnerability deltas from Qualys scan exports.

    Supports both JSON snapshots and CSV-to-JSON conversion for comparison.
    """

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or (Config.BASE_DIR / "data")

    def load_snapshot(self, filepath: Path) -> dict:
        """Load a vulnerability snapshot from JSON file."""
        if not filepath.exists():
            raise FileNotFoundError(f"Snapshot not found: {filepath}")
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        logger.info("Loaded snapshot: %s (%d vulnerabilities)", filepath.name, len(data.get("vulnerabilities", [])))
        return data

    def save_snapshot(self, df: pd.DataFrame, label: str = "today") -> Path:
        """Convert a parsed DataFrame to JSON snapshot and save it.

        Args:
            df: Normalized vulnerability DataFrame
            label: Filename label ('today', 'yesterday', or date string)

        Returns:
            Path to saved JSON file
        """
        records = []
        for _, row in df.iterrows():
            record = {
                "qid": str(row.get("QID", "")),
                "hostname": str(row.get("Hostname", "")),
                "ip_address": str(row.get("IP Address", "")),
                "severity": int(row.get("Severity", 1)),
                "severity_label": str(row.get("Severity_Label", "Informational")),
                "title": str(row.get("Vulnerability Title", "")),
                "os": str(row.get("Operating System", "")),
                "last_detected": str(row.get("Last Detected", "")),
                "asset_group": str(row.get("Asset Group", "")),
            }
            records.append(record)

        snapshot = {
            "scan_date": datetime.now().isoformat(),
            "label": label,
            "total_count": len(records),
            "vulnerabilities": records,
        }

        output_path = self.data_dir / f"snapshot_{label}.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2, default=str)

        logger.info("Snapshot saved: %s (%d records)", output_path.name, len(records))
        return output_path

    def get_yesterday_snapshot(self) -> Optional[dict]:
        """Attempt to load yesterday's snapshot."""
        yesterday_path = self.data_dir / "snapshot_yesterday.json"
        if yesterday_path.exists():
            return self.load_snapshot(yesterday_path)

        # Try date-based naming
        yesterday_date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        dated_path = self.data_dir / f"snapshot_{yesterday_date}.json"
        if dated_path.exists():
            return self.load_snapshot(dated_path)

        logger.warning("No yesterday snapshot found. Delta analysis will be skipped on first run.")
        return None

    def rotate_snapshots(self) -> None:
        """Rotate today's snapshot to yesterday's for next run."""
        today_path = self.data_dir / "snapshot_today.json"
        yesterday_path = self.data_dir / "snapshot_yesterday.json"

        if today_path.exists():
            if yesterday_path.exists():
                yesterday_path.unlink()
            today_path.rename(yesterday_path)
            logger.info("Rotated snapshot: today -> yesterday")
