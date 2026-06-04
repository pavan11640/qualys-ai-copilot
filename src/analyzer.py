"""Vulnerability data analyzer — grouping, statistics, and prioritization."""

import logging
from dataclasses import dataclass, field
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityStats:
    """Container for vulnerability statistics."""

    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0
    top_affected_hosts: list = field(default_factory=list)
    top_recurring_cves: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "Total Vulnerabilities": self.total,
            "Critical": self.critical,
            "High": self.high,
            "Medium": self.medium,
            "Low": self.low,
            "Informational": self.informational,
            "Top Affected Hosts": self.top_affected_hosts,
            "Top Recurring CVEs": self.top_recurring_cves,
        }

    def to_summary_text(self) -> str:
        lines = [
            f"Total Vulnerabilities: {self.total}",
            f"Critical: {self.critical}",
            f"High: {self.high}",
            f"Medium: {self.medium}",
            f"Low: {self.low}",
            f"Informational: {self.informational}",
            "",
            "Top Affected Hosts:",
        ]
        for host, count in self.top_affected_hosts:
            lines.append(f"  - {host}: {count} vulnerabilities")
        lines.append("")
        lines.append("Top Recurring CVEs:")
        for cve, count in self.top_recurring_cves:
            lines.append(f"  - {cve}: {count} occurrences")
        return "\n".join(lines)


class VulnerabilityAnalyzer:
    """Analyzes parsed vulnerability data to produce statistics and groupings."""

    def __init__(self, df: pd.DataFrame):
        self.df = df

    def compute_statistics(self, top_n: int = 10) -> VulnerabilityStats:
        """Compute summary statistics from vulnerability data."""
        logger.info("Computing vulnerability statistics")
        stats = VulnerabilityStats(total=len(self.df))

        if "Severity_Label" in self.df.columns:
            counts = self.df["Severity_Label"].value_counts()
            stats.critical = int(counts.get("Critical", 0))
            stats.high = int(counts.get("High", 0))
            stats.medium = int(counts.get("Medium", 0))
            stats.low = int(counts.get("Low", 0))
            stats.informational = int(counts.get("Informational", 0))

        if "Hostname" in self.df.columns:
            host_counts = (
                self.df[self.df["Hostname"] != "Unknown"]["Hostname"]
                .value_counts()
                .head(top_n)
            )
            stats.top_affected_hosts = list(host_counts.items())

        if "CVE" in self.df.columns:
            cve_counts = (
                self.df[self.df["CVE"] != "Unknown"]["CVE"]
                .value_counts()
                .head(top_n)
            )
            stats.top_recurring_cves = list(cve_counts.items())

        logger.info("Statistics: %d total, %d critical, %d high", stats.total, stats.critical, stats.high)
        return stats

    def group_by_severity(self) -> dict[str, pd.DataFrame]:
        """Group vulnerabilities by severity label."""
        if "Severity_Label" not in self.df.columns:
            return {}
        return {name: group for name, group in self.df.groupby("Severity_Label")}

    def group_by_host(self) -> dict[str, pd.DataFrame]:
        """Group vulnerabilities by hostname."""
        if "Hostname" not in self.df.columns:
            return {}
        return {name: group for name, group in self.df.groupby("Hostname")}

    def group_by_cve(self) -> dict[str, pd.DataFrame]:
        """Group vulnerabilities by CVE identifier."""
        if "CVE" not in self.df.columns:
            return {}
        return {name: group for name, group in self.df.groupby("CVE")}

    def group_by_asset_group(self) -> dict[str, pd.DataFrame]:
        """Group vulnerabilities by asset group."""
        if "Asset Group" not in self.df.columns:
            return {}
        return {name: group for name, group in self.df.groupby("Asset Group")}

    def get_critical_findings(self) -> pd.DataFrame:
        """Return only critical severity findings."""
        if "Severity_Label" in self.df.columns:
            return self.df[self.df["Severity_Label"] == "Critical"]
        return pd.DataFrame()

    def get_high_findings(self) -> pd.DataFrame:
        """Return only high severity findings."""
        if "Severity_Label" in self.df.columns:
            return self.df[self.df["Severity_Label"] == "High"]
        return pd.DataFrame()

    def prepare_findings_for_ai(self, max_records: int = 50) -> str:
        """Prepare a text representation of top findings for AI analysis."""
        critical = self.get_critical_findings()
        high = self.get_high_findings()
        priority_df = pd.concat([critical, high]).head(max_records)

        if priority_df.empty:
            priority_df = self.df.head(max_records)

        lines = []
        for _, row in priority_df.iterrows():
            entry = []
            for col in priority_df.columns:
                if col != "Severity":
                    entry.append(f"{col}: {row[col]}")
            lines.append(" | ".join(entry))
            lines.append("---")

        return "\n".join(lines)
