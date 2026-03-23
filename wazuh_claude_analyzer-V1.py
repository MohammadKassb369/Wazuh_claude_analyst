#!/usr/bin/env python3
"""
Wazuh High-Level Alert Analyzer with Claude AI
================================================
Monitors Wazuh alerts with level > 12 and uses Claude API
to perform intelligent security investigation and summarization.

Usage:
    python3 wazuh_claude_analyzer.py

Requirements:
    pip install anthropic requests
"""

import json
import os
import sys
import time
import logging
import argparse
from datetime import datetime, timezone
from pathlib import Path
import anthropic

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

# Wazuh settings
WAZUH_ALERTS_JSON = "/var/ossec/logs/alerts/alerts.json"   # default path on manager
ALERT_LEVEL_THRESHOLD = 8                                  # analyze alerts ABOVE this level

# Claude API settings
CLAUDE_MODEL = "claude-sonnet-4-20250514"
CLAUDE_MAX_TOKENS = 1024

# Output / logging
LOG_FILE = "/var/ossec/logs/claude_analysis.log"
OUTPUT_DIR = "/var/ossec/logs/claude_reports"

# Polling interval in seconds (when running in daemon/watch mode)
POLL_INTERVAL = 10

# ──────────────────────────────────────────────
# Logging setup
# ──────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, mode="a") if Path(LOG_FILE).parent.exists() else logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# Wazuh alert reader
# ──────────────────────────────────────────────

def read_alerts_from_file(filepath: str) -> list[dict]:
    """
    Read Wazuh alerts.json (newline-delimited JSON format).
    Returns a list of alert dicts.
    """
    alerts = []
    path = Path(filepath)
    if not path.exists():
        logger.error(f"Alert file not found: {filepath}")
        return alerts

    with open(filepath, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
                alerts.append(alert)
            except json.JSONDecodeError as e:
                logger.warning(f"Skipping malformed JSON line: {e}")

    return alerts


def filter_high_level_alerts(alerts: list[dict], threshold: int = ALERT_LEVEL_THRESHOLD) -> list[dict]:
    """Return only alerts whose rule level is strictly above `threshold`."""
    high = []
    for alert in alerts:
        try:
            level = int(alert.get("rule", {}).get("level", 0))
            if level > threshold:
                high.append(alert)
        except (ValueError, TypeError):
            pass
    return high


def tail_new_alerts(filepath: str, last_position: int) -> tuple[list[dict], int]:
    """
    Read only new lines added since `last_position` bytes.
    Returns (new_alerts, new_position).
    """
    alerts = []
    path = Path(filepath)
    if not path.exists():
        return alerts, last_position

    with open(filepath, "r", encoding="utf-8") as fh:
        fh.seek(last_position)
        for line in fh:
            line_stripped = line.strip()
            if not line_stripped:
                continue
            try:
                alert = json.loads(line_stripped)
                alerts.append(alert)
            except json.JSONDecodeError:
                pass
        new_position = fh.tell()

    return alerts, new_position


# ──────────────────────────────────────────────
# Claude AI analysis
# ──────────────────────────────────────────────

def build_analysis_prompt(alert: dict) -> str:
    """Build a detailed security-focused prompt for Claude."""
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})
    timestamp = alert.get("timestamp", "unknown")

    prompt = f"""You are a senior cybersecurity analyst. Analyze the following Wazuh security alert and provide a concise but thorough investigation report.

## Alert Details
- **Timestamp**: {timestamp}
- **Rule ID**: {rule.get("id", "N/A")}
- **Rule Level**: {rule.get("level", "N/A")} (scale 0–15, critical threshold >12)
- **Rule Description**: {rule.get("description", "N/A")}
- **Rule Groups**: {", ".join(rule.get("groups", [])) or "N/A"}
- **MITRE ATT&CK**: {json.dumps(rule.get("mitre", {})) if rule.get("mitre") else "N/A"}

## Source Agent
- **Agent ID**: {agent.get("id", "N/A")}
- **Agent Name**: {agent.get("name", "N/A")}
- **Agent IP**: {agent.get("ip", "N/A")}

## Raw Event Data
```json
{json.dumps(data, indent=2)}
```

## Full Alert JSON
```json
{json.dumps(alert, indent=2)}
```

## Required Analysis

Please provide:

1. **Threat Summary** (2-3 sentences): What happened and why it is critical.
2. **Attack Vector / Technique**: How the attacker likely executed this (reference MITRE ATT&CK if applicable).
3. **Affected Assets**: Which systems/services are at risk.
4. **Severity Assessment**: Confirm or refine the severity level with reasoning.
5. **Immediate Actions**: Top 3-5 containment/remediation steps the SOC team should take RIGHT NOW.
6. **Investigation Checklist**: Additional log sources or indicators to examine.
7. **False Positive Likelihood**: Low / Medium / High — with reasoning.

Keep the report actionable and prioritized for a SOC analyst who must respond within minutes.
"""
    return prompt


def analyze_alert_with_claude(alert: dict, client: anthropic.Anthropic) -> str:
    """Send alert to Claude API and return the analysis text."""
    prompt = build_analysis_prompt(alert)

    try:
        message = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=CLAUDE_MAX_TOKENS,
            messages=[
                {"role": "user", "content": prompt}
            ],
        )
        return message.content[0].text
    except anthropic.APIConnectionError as e:
        return f"[ERROR] Could not connect to Claude API: {e}"
    except anthropic.RateLimitError:
        return "[ERROR] Claude API rate limit reached. Retry later."
    except anthropic.APIStatusError as e:
        return f"[ERROR] Claude API error {e.status_code}: {e.message}"


# ──────────────────────────────────────────────
# Report saving
# ──────────────────────────────────────────────

def save_report(alert: dict, analysis: str, output_dir: str) -> str:
    """Save the analysis report to a file and return the path."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    rule_id = alert.get("rule", {}).get("id", "unknown")
    level = alert.get("rule", {}).get("level", "unknown")
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"alert_L{level}_rule{rule_id}_{ts}.txt"
    filepath = Path(output_dir) / filename

    report_lines = [
        "=" * 70,
        "WAZUH HIGH-LEVEL ALERT — CLAUDE AI SECURITY ANALYSIS",
        "=" * 70,
        f"Generated   : {datetime.now(timezone.utc).isoformat()}",
        f"Rule ID     : {rule_id}",
        f"Rule Level  : {level}",
        f"Description : {alert.get('rule', {}).get('description', 'N/A')}",
        f"Agent       : {alert.get('agent', {}).get('name', 'N/A')} "
                       f"({alert.get('agent', {}).get('ip', 'N/A')})",
        "-" * 70,
        "CLAUDE AI ANALYSIS",
        "-" * 70,
        analysis,
        "=" * 70,
        "RAW ALERT",
        "-" * 70,
        json.dumps(alert, indent=2),
        "=" * 70,
    ]

    filepath.write_text("\n".join(report_lines), encoding="utf-8")
    return str(filepath)


# ──────────────────────────────────────────────
# Pretty console output
# ──────────────────────────────────────────────

def print_report(alert: dict, analysis: str, report_path: str):
    rule = alert.get("rule", {})
    print("\n" + "=" * 70)
    print("🔴  HIGH-LEVEL WAZUH ALERT DETECTED — CLAUDE AI INVESTIGATION")
    print("=" * 70)
    print(f"  Rule ID    : {rule.get('id')}")
    print(f"  Level      : {rule.get('level')}  (threshold >{ALERT_LEVEL_THRESHOLD})")
    print(f"  Description: {rule.get('description')}")
    print(f"  Agent      : {alert.get('agent', {}).get('name')}  "
          f"({alert.get('agent', {}).get('ip')})")
    print("-" * 70)
    print("🤖  CLAUDE ANALYSIS")
    print("-" * 70)
    print(analysis)
    print("-" * 70)
    print(f"📄  Report saved → {report_path}")
    print("=" * 70 + "\n")


# ──────────────────────────────────────────────
# Main modes: single-run or watch (daemon)
# ──────────────────────────────────────────────

def run_once(alert_file: str, client: anthropic.Anthropic):
    """Analyze all high-level alerts currently in the alert file."""
    logger.info(f"Reading alerts from: {alert_file}")
    alerts = read_alerts_from_file(alert_file)
    high_alerts = filter_high_level_alerts(alerts)

    if not high_alerts:
        logger.info(f"No alerts above level {ALERT_LEVEL_THRESHOLD} found.")
        return

    logger.info(f"Found {len(high_alerts)} alert(s) above level {ALERT_LEVEL_THRESHOLD}.")

    for i, alert in enumerate(high_alerts, 1):
        level = alert.get("rule", {}).get("level", "?")
        desc = alert.get("rule", {}).get("description", "?")
        logger.info(f"[{i}/{len(high_alerts)}] Analyzing level-{level} alert: {desc}")

        analysis = analyze_alert_with_claude(alert, client)
        report_path = save_report(alert, analysis, OUTPUT_DIR)
        print_report(alert, analysis, report_path)


def run_watch(alert_file: str, client: anthropic.Anthropic):
    """
    Continuously tail the alert file and analyze new high-level alerts as
    they arrive (daemon / watch mode).
    """
    logger.info(f"👀  Watch mode — tailing {alert_file}  (poll every {POLL_INTERVAL}s)")
    logger.info(f"    Analyzing alerts with level > {ALERT_LEVEL_THRESHOLD}")

    # Start at end of file so we only catch NEW alerts
    path = Path(alert_file)
    position = path.stat().st_size if path.exists() else 0

    try:
        while True:
            new_alerts, position = tail_new_alerts(alert_file, position)
            high_alerts = filter_high_level_alerts(new_alerts)

            for alert in high_alerts:
                level = alert.get("rule", {}).get("level", "?")
                desc = alert.get("rule", {}).get("description", "?")
                logger.info(f"🔴 New level-{level} alert: {desc}")

                analysis = analyze_alert_with_claude(alert, client)
                report_path = save_report(alert, analysis, OUTPUT_DIR)
                print_report(alert, analysis, report_path)

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        logger.info("Watch mode stopped by user.")


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def main():
    global ALERT_LEVEL_THRESHOLD
    
    parser = argparse.ArgumentParser(
        description="Wazuh High-Level Alert Analyzer with Claude AI"
    )
    parser.add_argument(
        "--mode",
        choices=["once", "watch"],
        default="once",
        help="'once' analyzes existing alerts; 'watch' tails the file for new alerts (default: once)",
    )
    parser.add_argument(
        "--alerts-file",
        default=WAZUH_ALERTS_JSON,
        help=f"Path to Wazuh alerts.json (default: {WAZUH_ALERTS_JSON})",
    )
    parser.add_argument(
        "--level",
        type=int,
        default=ALERT_LEVEL_THRESHOLD,
        help=f"Alert level threshold — analyze alerts ABOVE this value (default: {ALERT_LEVEL_THRESHOLD})",
    )
    args = parser.parse_args()

    # Validate API key
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        logger.error("ANTHROPIC_API_KEY environment variable is not set.")
        logger.error("Export it: export ANTHROPIC_API_KEY='sk-ant-...'")
        sys.exit(1)

    # Override threshold if provided
    ALERT_LEVEL_THRESHOLD = args.level

    client = anthropic.Anthropic(api_key=api_key)
    logger.info(f"Claude model: {CLAUDE_MODEL}")
    logger.info(f"Alert threshold: level > {ALERT_LEVEL_THRESHOLD}")

    if args.mode == "watch":
        run_watch(args.alerts_file, client)
    else:
        run_once(args.alerts_file, client)


if __name__ == "__main__":
    main()
