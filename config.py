"""Application configuration module."""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent


class Config:
    """Central configuration for the Qualys AI Copilot application."""

    # AWS Configuration (Primary - Amazon Bedrock)
    AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")
    AWS_PROFILE: str = os.getenv("AWS_PROFILE", "default")
    BEDROCK_MODEL_ID: str = os.getenv(
        "BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20241022-v2:0"
    )

    # Application Settings
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    INPUT_CSV: Path = BASE_DIR / os.getenv("INPUT_CSV", "data/qualys_export.csv")
    OUTPUT_DIR: Path = BASE_DIR / os.getenv("OUTPUT_DIR", "reports")
    MAX_TOKENS: int = int(os.getenv("MAX_TOKENS", "4096"))
    PROMPTS_DIR: Path = BASE_DIR / "prompts"
    TEMPLATES_DIR: Path = BASE_DIR / "templates"

    # Qualys API (for future direct API integration)
    QUALYS_API_URL: str = os.getenv("QUALYS_API_URL", "")
    QUALYS_USERNAME: str = os.getenv("QUALYS_USERNAME", "")
    QUALYS_PASSWORD: str = os.getenv("QUALYS_PASSWORD", "")

    SEVERITY_MAP: dict = {
        5: "Critical",
        4: "High",
        3: "Medium",
        2: "Low",
        1: "Informational",
    }

    CSV_FIELDS: list = [
        "Hostname",
        "IP Address",
        "Operating System",
        "QID",
        "CVE",
        "Severity",
        "Vulnerability Title",
        "Vulnerability Category",
        "Last Detected",
        "Asset Group",
    ]
