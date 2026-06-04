"""Qualys CSV report parser and data normalizer."""

import logging
from pathlib import Path
from typing import Optional

import pandas as pd

from config import Config

logger = logging.getLogger(__name__)

# Mapping from actual Qualys column names to our normalized names
COLUMN_MAP = {
    "Asset Name": "Hostname",
    "Asset IPV4": "IP Address",
    "Operating System": "Operating System",
    "QID": "QID",
    "CVEIDS": "CVE",
    "Title": "Vulnerability Title",
    "Category": "Vulnerability Category",
    "Detected Last": "Last Detected",
    "Asset Tags": "Asset Group",
}


class QualysParser:
    """Parses and normalizes Qualys vulnerability management CSV exports."""

    def __init__(self, csv_path: Optional[Path] = None):
        self.csv_path = csv_path or Config.INPUT_CSV
        self.raw_df: Optional[pd.DataFrame] = None
        self.df: Optional[pd.DataFrame] = None

    def read_csv(self) -> pd.DataFrame:
        """Read the Qualys CSV export file, skipping metadata header lines."""
        logger.info("Reading CSV file: %s", self.csv_path)
        if not self.csv_path.exists():
            raise FileNotFoundError(f"CSV file not found: {self.csv_path}")

        # Find the main data header row (the one with detailed columns like Asset Name)
        header_row = self._find_data_header()
        logger.info("Detected data header at row %d", header_row)

        self.raw_df = pd.read_csv(
            self.csv_path,
            skiprows=header_row,
            encoding="utf-8",
            on_bad_lines="skip",
            low_memory=False,
        )
        logger.info("Loaded %d rows from CSV", len(self.raw_df))
        return self.raw_df

    def _find_data_header(self) -> int:
        """Find the row index of the main data header (with Asset Name/Title columns)."""
        with open(self.csv_path, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                # Look for the detailed data header that has columns like Title, Asset Name, etc.
                if "Asset Name" in line and "Title" in line and "Severity" in line:
                    return i
        # Fallback: try the first QID header with many columns
        with open(self.csv_path, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if line.startswith("QID,") and "Detected Last" in line:
                    return i
        return 0

    def normalize(self) -> pd.DataFrame:
        """Normalize and clean the vulnerability data."""
        if self.raw_df is None:
            self.read_csv()

        df = self.raw_df.copy()

        # Remove sub-header rows and summary rows that appear mid-file
        if "Title" in df.columns:
            df = df[df["Title"].notna() & (df["Title"] != "TITLE") & (df["Title"] != "Title")].copy()
        if "Asset Name" in df.columns:
            df = df[df["Asset Name"] != "Asset Name"].copy()  # remove repeated header rows
        if "QID" in df.columns:
            # Remove summary-only rows (rows where QID matches but no Asset Id)
            if "Asset Id" in df.columns:
                df = df[df["Asset Id"].notna()].copy()

        # Rename columns to our standard names
        rename_map = {}
        for src, dst in COLUMN_MAP.items():
            if src in df.columns and src != dst:
                rename_map[src] = dst
        df = df.rename(columns=rename_map)

        # Handle severity — prefer "Severity KB" column from Qualys
        sev_col = None
        if "Severity KB" in df.columns:
            sev_col = "Severity KB"
        elif "Severity" in df.columns:
            sev_col = "Severity"

        if sev_col:
            df["Severity"] = pd.to_numeric(df[sev_col], errors="coerce").fillna(1).astype(int)
            df["Severity_Label"] = df["Severity"].map(Config.SEVERITY_MAP).fillna("Informational")

        # Clean string fields
        for col in ["Hostname", "IP Address", "CVE", "Vulnerability Title", "Asset Group"]:
            if col in df.columns:
                df[col] = df[col].astype(str).str.strip().replace("nan", "Unknown")

        # Parse dates
        if "Last Detected" in df.columns:
            df["Last Detected"] = pd.to_datetime(df["Last Detected"], errors="coerce")

        # Keep only relevant columns that exist
        keep_cols = [c for c in Config.CSV_FIELDS + ["Severity_Label"] if c in df.columns]
        df = df[keep_cols].copy()

        self.df = df
        logger.info("Normalization complete. %d records processed.", len(self.df))
        return self.df

    def get_dataframe(self) -> pd.DataFrame:
        """Return the normalized DataFrame."""
        if self.df is None:
            self.normalize()
        return self.df
