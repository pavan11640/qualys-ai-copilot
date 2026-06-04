FROM python:3.12-slim

LABEL maintainer="Qualys AI Copilot"
LABEL description="Qualys AI Analyst Copilot — Vulnerability Assessment Report Generator"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libfontconfig1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/reports

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["python", "-m", "src.main"]
