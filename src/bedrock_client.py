"""Amazon Bedrock client — Claude 3.5 Sonnet integration for vulnerability analysis.

This module provides:
- Direct invocation of Claude 3.5 Sonnet via boto3 bedrock-runtime
- Day-over-day delta comparison engine (new CVEs, resolved vulns, risk changes)
- Structured prompt engineering for executive-grade remediation insights
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

from config import Config

logger = logging.getLogger(__name__)


@dataclass
class DeltaResult:
    """Container for day-over-day vulnerability delta analysis."""

    new_vulnerabilities: list = field(default_factory=list)
    resolved_vulnerabilities: list = field(default_factory=list)
    new_critical_risks: list = field(default_factory=list)
    severity_changes: dict = field(default_factory=dict)
    total_yesterday: int = 0
    total_today: int = 0
    net_change: int = 0

    def to_summary(self) -> str:
        lines = [
            "## Day-over-Day Delta Summary",
            f"- Yesterday's Total: {self.total_yesterday}",
            f"- Today's Total: {self.total_today}",
            f"- Net Change: {'+' if self.net_change > 0 else ''}{self.net_change}",
            f"- New Vulnerabilities Introduced: {len(self.new_vulnerabilities)}",
            f"- Vulnerabilities Resolved: {len(self.resolved_vulnerabilities)}",
            f"- New Critical Risks: {len(self.new_critical_risks)}",
            "",
            "### Severity Breakdown Changes:",
        ]
        for sev, change in self.severity_changes.items():
            direction = "+" if change > 0 else ""
            lines.append(f"  - {sev}: {direction}{change}")
        return "\n".join(lines)


class BedrockClient:
    """Production-grade Amazon Bedrock client for Claude 3.5 Sonnet.

    Handles:
    - Model invocation with retry and error handling
    - Day-over-day delta computation
    - Structured prompt construction for vulnerability analysis
    - Executive report generation
    """

    def __init__(self):
        boto_config = BotoConfig(
            retries={"max_attempts": 3, "mode": "adaptive"},
            read_timeout=120,
            connect_timeout=10,
        )
        session = boto3.Session(
            region_name=Config.AWS_REGION,
            profile_name=Config.AWS_PROFILE if Config.AWS_PROFILE != "default" else None,
        )
        self.client = session.client("bedrock-runtime", config=boto_config)
        self.model_id = Config.BEDROCK_MODEL_ID
        self.max_tokens = Config.MAX_TOKENS
        logger.info("Bedrock client initialized: region=%s model=%s", Config.AWS_REGION, self.model_id)

    def invoke(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Invoke Claude 3.5 Sonnet via Bedrock Messages API."""
        logger.info("Invoking Bedrock model: %s", self.model_id)

        messages = [{"role": "user", "content": [{"type": "text", "text": prompt}]}]

        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": self.max_tokens,
            "messages": messages,
            "temperature": 0.2,
            "top_p": 0.9,
        }
        if system_prompt:
            body["system"] = system_prompt

        try:
            response = self.client.invoke_model(
                modelId=self.model_id,
                contentType="application/json",
                accept="application/json",
                body=json.dumps(body),
            )
            response_body = json.loads(response["body"].read())
            output_text = response_body["content"][0]["text"]
            tokens_in = response_body.get("usage", {}).get("input_tokens", 0)
            tokens_out = response_body.get("usage", {}).get("output_tokens", 0)
            logger.info(
                "Bedrock response: %d chars, tokens_in=%d, tokens_out=%d",
                len(output_text), tokens_in, tokens_out,
            )
            return output_text

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "ThrottlingException":
                logger.error("Bedrock throttled. Increase provisioned throughput or retry.")
            elif error_code == "ModelNotReadyException":
                logger.error("Model not ready. Ensure Claude 3.5 Sonnet is enabled in your region.")
            elif error_code == "AccessDeniedException":
                logger.error("Access denied. Enable model access in Bedrock console.")
            else:
                logger.error("Bedrock API error [%s]: %s", error_code, e)
            raise

    # ------------------------------------------------------------------
    # Delta Comparison Engine
    # ------------------------------------------------------------------

    def compute_delta(self, yesterday_data: dict, today_data: dict) -> DeltaResult:
        """Compare yesterday's and today's vulnerability data to produce delta insights.

        Args:
            yesterday_data: Dict with keys 'vulnerabilities' (list of dicts with at least
                           'qid', 'hostname', 'severity', 'title' fields)
            today_data: Same structure as yesterday_data

        Returns:
            DeltaResult with new, resolved, and changed vulnerabilities
        """
        logger.info("Computing day-over-day delta")

        yesterday_set = {
            (v.get("qid"), v.get("hostname"))
            for v in yesterday_data.get("vulnerabilities", [])
        }
        today_set = {
            (v.get("qid"), v.get("hostname"))
            for v in today_data.get("vulnerabilities", [])
        }

        today_lookup = {
            (v.get("qid"), v.get("hostname")): v
            for v in today_data.get("vulnerabilities", [])
        }
        yesterday_lookup = {
            (v.get("qid"), v.get("hostname")): v
            for v in yesterday_data.get("vulnerabilities", [])
        }

        new_keys = today_set - yesterday_set
        resolved_keys = yesterday_set - today_set

        new_vulns = [today_lookup[k] for k in new_keys]
        resolved_vulns = [yesterday_lookup[k] for k in resolved_keys]
        new_critical = [v for v in new_vulns if v.get("severity", 0) >= 4]

        # Severity breakdown changes
        sev_labels = {5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Informational"}
        sev_yesterday = {}
        sev_today = {}
        for v in yesterday_data.get("vulnerabilities", []):
            label = sev_labels.get(v.get("severity", 1), "Unknown")
            sev_yesterday[label] = sev_yesterday.get(label, 0) + 1
        for v in today_data.get("vulnerabilities", []):
            label = sev_labels.get(v.get("severity", 1), "Unknown")
            sev_today[label] = sev_today.get(label, 0) + 1

        severity_changes = {}
        for label in sev_labels.values():
            diff = sev_today.get(label, 0) - sev_yesterday.get(label, 0)
            if diff != 0:
                severity_changes[label] = diff

        result = DeltaResult(
            new_vulnerabilities=new_vulns,
            resolved_vulnerabilities=resolved_vulns,
            new_critical_risks=new_critical,
            severity_changes=severity_changes,
            total_yesterday=len(yesterday_data.get("vulnerabilities", [])),
            total_today=len(today_data.get("vulnerabilities", [])),
            net_change=len(today_data.get("vulnerabilities", [])) - len(yesterday_data.get("vulnerabilities", [])),
        )
        logger.info(
            "Delta computed: +%d new, -%d resolved, %d new critical",
            len(new_vulns), len(resolved_vulns), len(new_critical),
        )
        return result

    # ------------------------------------------------------------------
    # AI Analysis Methods
    # ------------------------------------------------------------------

    def analyze_vulnerabilities(self, vulnerability_data: str) -> str:
        """Generate AI vulnerability analysis from findings data."""
        system_prompt = (
            "You are a senior cybersecurity analyst and CISO advisor. "
            "Analyze vulnerability data and produce actionable, structured remediation guidance. "
            "Be precise, reference specific CVEs/QIDs, and prioritize by business risk."
        )
        prompt = self._build_analysis_prompt(vulnerability_data)
        return self.invoke(prompt, system_prompt=system_prompt)

    def analyze_delta(self, delta: DeltaResult) -> str:
        """Send delta results to Claude for intelligent analysis."""
        system_prompt = (
            "You are a senior cybersecurity analyst performing day-over-day vulnerability trending. "
            "Identify patterns, escalating risks, and provide strategic remediation priorities."
        )
        prompt = self._build_delta_prompt(delta)
        return self.invoke(prompt, system_prompt=system_prompt)

    def generate_executive_report(self, statistics: str, findings: str) -> str:
        """Generate an executive-level report using Claude 3.5 Sonnet."""
        system_prompt = (
            "You are a CISO advisor generating an executive vulnerability assessment report. "
            "Write for C-level audience. Be concise, data-driven, and action-oriented."
        )
        prompt = self._build_executive_prompt(statistics, findings)
        return self.invoke(prompt, system_prompt=system_prompt)

    # ------------------------------------------------------------------
    # Prompt Construction
    # ------------------------------------------------------------------

    def _build_analysis_prompt(self, vulnerability_data: str) -> str:
        return f"""Analyze the following vulnerability findings and produce a structured assessment.

## Vulnerability Data
{vulnerability_data}

## Required Output (Markdown format)

For each critical and high severity vulnerability cluster, provide:

### A. Vulnerability Description
Technical explanation of the vulnerability mechanism.

### B. Business Impact
How exploitation would affect business operations, data integrity, or compliance.

### C. Exploitation Likelihood
Rate as Critical/High/Medium/Low with reasoning based on:
- Public exploit availability
- Network exposure
- Authentication requirements

### D. Remediation Recommendation
Specific patch versions, configuration changes, or compensating controls.

### E. Validation Steps
Commands or procedures to verify successful remediation.

### F. Patch Priority
- P1 (Immediate - within 24h): Active exploitation or Critical + Internet-facing
- P2 (Urgent - within 7 days): High severity or Critical + Internal
- P3 (Standard - within 30 days): Medium severity
- P4 (Scheduled - within 90 days): Low severity

### G. Executive Risk Summary
One paragraph suitable for board-level communication.
"""

    def _build_delta_prompt(self, delta: DeltaResult) -> str:
        new_vulns_text = ""
        for v in delta.new_vulnerabilities[:30]:
            new_vulns_text += (
                f"- QID:{v.get('qid')} | {v.get('title','Unknown')} | "
                f"Severity:{v.get('severity')} | Host:{v.get('hostname')}\n"
            )

        resolved_text = ""
        for v in delta.resolved_vulnerabilities[:20]:
            resolved_text += (
                f"- QID:{v.get('qid')} | {v.get('title','Unknown')} | Host:{v.get('hostname')}\n"
            )

        return f"""## Day-over-Day Vulnerability Delta Analysis

### Statistical Summary
{delta.to_summary()}

### Newly Introduced Vulnerabilities (Top 30)
{new_vulns_text if new_vulns_text else "None"}

### Resolved Vulnerabilities (Top 20)
{resolved_text if resolved_text else "None"}

---

## Required Analysis (Markdown output)

1. **Trend Assessment**: Is the security posture improving or degrading? Quantify.
2. **New Critical Risks**: For each new critical/high finding, explain the risk and immediate action needed.
3. **Top Recurring Patterns**: Identify vulnerability categories appearing repeatedly across hosts.
4. **Remediation Priorities**: Ordered list of top 5 actions by risk reduction impact.
5. **Positive Progress**: Acknowledge resolved items and team effectiveness.
6. **7-Day Forecast**: Based on the trend, what should the team prepare for?
"""

    def _build_executive_prompt(self, statistics: str, findings: str) -> str:
        return f"""## Current Vulnerability Statistics
{statistics}

## Detailed AI Analysis
{findings}

---

Generate a comprehensive executive vulnerability assessment report with these sections:

1. **Executive Summary** (3-4 sentences max)
2. **Overall Risk Posture** (Critical/High/Medium/Low with justification)
3. **Critical Vulnerabilities** (bullet points with immediate actions)
4. **High Risk Vulnerabilities** (grouped by category)
5. **Most Affected Assets** (top 5 with vulnerability density)
6. **Top Remediation Priorities** (ordered by business impact reduction)
7. **Recommended Actions** (strategic + tactical, with owners and timelines)
8. **Conclusion** (forward-looking posture statement)

Format as professional markdown. Use tables where appropriate.
"""
