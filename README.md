# Qualys AI Analyst Copilot

**AI-Powered Vulnerability Management Automation using Amazon Bedrock & Claude 3.5 Sonnet**

An enterprise-grade Python application that ingests Qualys Vulnerability Management scan exports, performs day-over-day delta analysis, and generates executive-level remediation reports powered by Generative AI.

---

## Overview

Traditional vulnerability management workflows involve manual CSV triage, spreadsheet-based tracking, and delayed remediation cycles. **Qualys AI Copilot** eliminates these bottlenecks by:

- Automatically parsing Qualys VM scan exports (CSV)
- Computing day-over-day vulnerability deltas (new risks, resolved items, severity shifts)
- Leveraging **Amazon Bedrock (Claude 3.5 Sonnet)** for intelligent risk analysis and remediation planning
- Generating executive reports in **HTML, Markdown, and PDF** formats

---

## Architecture & Workflow

```
+------------------+     +-------------------+     +------------------------+
|   Qualys VM      |     |   Delta Engine    |     |   Amazon Bedrock       |
|   CSV Export     +---->+   (Day-over-Day   +---->+   Claude 3.5 Sonnet    |
|                  |     |    Comparison)    |     |                        |
+------------------+     +-------------------+     +----------+-------------+
                                                              |
                         +-------------------+                |
                         |  Report Generator |<---------------+
                         |  (HTML/MD/PDF)    |
                         +-------------------+
                                |
                                v
                    +------------------------+
                    |  Executive Reports     |
                    |  - Risk Posture        |
                    |  - Remediation Plan    |
                    |  - Delta Trends        |
                    +------------------------+
```

**Pipeline Steps:**
1. **Ingest** — Parse Qualys CSV export, normalize severity ratings, extract asset metadata
2. **Analyze** — Compute statistics, group by severity/host/asset group
3. **Delta** — Compare today's scan against yesterday's snapshot to identify new/resolved vulnerabilities
4. **AI Enrichment** — Send prioritized findings to Claude 3.5 Sonnet for exploitation likelihood, business impact, and remediation steps
5. **Report** — Generate multi-format executive reports with trend analysis

---

## Prerequisites

- **Python 3.10+**
- **AWS Account** with Amazon Bedrock access
- **Claude 3.5 Sonnet** model enabled in your AWS region ([Enable in Bedrock Console](https://console.aws.amazon.com/bedrock/home#/modelaccess))
- **AWS CLI** configured with valid credentials (`aws configure`)

---

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/qualys-ai-copilot.git
cd qualys-ai-copilot

# Create and activate virtual environment
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows:
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your AWS region and profile
```

### AWS Credentials Setup

```bash
# Option 1: AWS CLI profile (recommended)
aws configure --profile default

# Option 2: Environment variables
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_REGION=us-east-1
```

Ensure your IAM user/role has the `bedrock:InvokeModel` permission for Claude 3.5 Sonnet.

---

## Usage

### Standard Analysis (Single Scan)

```bash
# Place your Qualys CSV export in the data/ directory
cp your_qualys_scan.csv data/qualys_export.csv

# Run the analysis pipeline
python -m src.main
```

### Day-over-Day Delta Analysis

Run the tool daily. On the second run onward, it automatically compares against yesterday's data:

```bash
# Day 1 - Baseline scan
python -m src.main

# Day 2 - Automatically detects delta from Day 1
python -m src.main
```

The tool automatically rotates snapshots: `snapshot_today.json` → `snapshot_yesterday.json`

### Custom CSV Path

```bash
# Override input file via environment variable
INPUT_CSV=data/scan_2024_03_15.csv python -m src.main
```

---

## Output

Reports are generated in `reports/` directory:

| Format | Use Case |
|--------|----------|
| **Markdown** (.md) | Version control, Confluence/Wiki integration |
| **HTML** (.html) | Browser viewing, email distribution |
| **PDF** (.pdf) | Executive presentations, compliance records |

---

## Project Structure

```
qualys-ai-copilot/
├── data/                      # Input CSVs & JSON snapshots
├── reports/                   # Generated reports (gitignored)
├── prompts/                   # AI prompt templates
├── templates/                 # Jinja2 HTML templates
├── src/
│   ├── __init__.py
│   ├── main.py                # Pipeline orchestrator
│   ├── parser.py              # Qualys CSV parser & normalizer
│   ├── analyzer.py            # Statistics & grouping engine
│   ├── delta_engine.py        # Day-over-day comparison
│   ├── bedrock_client.py      # Amazon Bedrock (Claude 3.5 Sonnet)
│   ├── report_generator.py    # Multi-format report generation
│   └── dashboard.py           # Terminal dashboard
├── config.py                  # Configuration management
├── requirements.txt           # Python dependencies
├── .env.example               # Environment template (safe to commit)
├── .gitignore                 # Security-aware gitignore
├── Dockerfile                 # Container deployment
└── README.md
```

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.10+ |
| AI/LLM | Amazon Bedrock (Claude 3.5 Sonnet) |
| Vulnerability Data | Qualys VM CSV Export |
| Data Processing | pandas |
| Report Generation | Jinja2, fpdf2, markdown |
| Cloud SDK | boto3 (AWS) |
| Configuration | python-dotenv |

---

## Security

- API credentials are managed via `.env` (never committed)
- `.gitignore` excludes all sensitive data, scan results, and generated reports
- AWS authentication uses IAM roles/profiles (no hardcoded keys)
- Vulnerability data stays within your AWS account (Bedrock does not store prompts)

---

## License

MIT
"# qualys-ai-copilot" 
