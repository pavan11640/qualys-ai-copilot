"""Terminal dashboard for vulnerability statistics display."""

import logging
import sys

from src.analyzer import VulnerabilityStats

logger = logging.getLogger(__name__)


class Dashboard:
    """Displays vulnerability statistics in the terminal."""

    def __init__(self, stats: VulnerabilityStats):
        self.stats = stats

    def display(self) -> None:
        """Print a formatted vulnerability summary to the terminal."""
        width = 60
        print()
        print("=" * width)
        print(f"{'QUALYS AI ANALYST COPILOT - VULNERABILITY DASHBOARD':^{width}}")
        print("=" * width)
        print()

        self._print_severity_bar("Critical", self.stats.critical, self.stats.total)
        self._print_severity_bar("High", self.stats.high, self.stats.total)
        self._print_severity_bar("Medium", self.stats.medium, self.stats.total)
        self._print_severity_bar("Low", self.stats.low, self.stats.total)
        self._print_severity_bar("Informational", self.stats.informational, self.stats.total)

        print()
        print(f"  {'Total Vulnerabilities:':<30} {self.stats.total}")
        print()
        print("-" * width)
        print("  Top Affected Hosts:")
        for host, count in self.stats.top_affected_hosts[:5]:
            print(f"    - {host:<35} {count:>4} findings")

        print()
        print("  Top Recurring CVEs:")
        for cve, count in self.stats.top_recurring_cves[:5]:
            print(f"    - {cve:<35} {count:>4} occurrences")

        print()
        print("=" * width)
        print()

    def _print_severity_bar(self, label: str, count: int, total: int) -> None:
        """Print a single severity bar."""
        pct = (count / total * 100) if total > 0 else 0
        bar_length = int(pct / 2.5)
        bar = "#" * bar_length
        print(f"  {label:<15} {count:>5}  {bar} ({pct:.1f}%)")
