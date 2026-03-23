#!/usr/bin/env python3
"""
Wazuh High-Level Alert Analyzer with Claude AI  — V3
======================================================
What's new in V3:
  • Writes every Claude analysis as a JSON event into
    /var/ossec/logs/claude_reports/claude_analysis.json
    (newline-delimited JSON — one event per line)
  • That file is picked up by Filebeat → Logstash → OpenSearch
    and becomes searchable/visible in the Wazuh dashboard under
    the index  wazuh-claude-*
  • Each JSON event carries the full alert metadata so the
    dashboard can filter/visualise by rule.id, rule.level, agent,
    MITRE technique, false-positive likelihood, etc.
  • The --no-opensearch flag skips the JSON write if you only
    want the text reports.

Usage:
    python3 wazuh_claude_analyzer-V3.py [--mode once|watch]
                                        [--alerts-file PATH]
                                        [--level N]
                                        [--dedup-window SECONDS]
                                        [--no-opensearch]

Requirements:
    pip install anthropic
"""

import hashlib
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

WAZUH_ALERTS_JSON        = "/var/ossec/logs/alerts/alerts.json"
ALERT_LEVEL_THRESHOLD    = 8

CUSTOM_RULE_MIN          = 100_000
CUSTOM_RULE_MAX          = 999_999

CLAUDE_MODEL             = "claude-sonnet-4-20250514"
CLAUDE_MAX_TOKENS        = 1024

LOG_FILE                 = "/var/ossec/logs/claude_analysis.log"
OUTPUT_DIR               = "/var/ossec/logs/claude_reports"

# ── NEW in V3 ──────────────────────────────────
# Newline-delimited JSON file consumed by Filebeat
# to push reports into the Wazuh/OpenSearch index.
OPENSEARCH_JSON_FILE     = "/var/ossec/logs/claude_reports/claude_analysis.json"
# ───────────────────────────────────────────────

POLL_INTERVAL            = 10
DEDUP_WINDOW_SECONDS     = 300


# ──────────────────────────────────────────────
# Logging setup
# ──────────────────────────────────────────────

def _build_handlers() -> list[logging.Handler]:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if Path(LOG_FILE).parent.exists():
        handlers.append(logging.FileHandler(LOG_FILE, mode="a"))
    return handlers

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=_build_handlers(),
)
logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# Alert fingerprinting & deduplication
# ──────────────────────────────────────────────

def _alert_fingerprint(alert: dict) -> str:
    rule     = alert.get("rule", {})
    agent    = alert.get("agent", {})
    data     = alert.get("data", {})
    raw_ts   = alert.get("timestamp", "")
    rule_id  = str(rule.get("id", ""))
    agent_id = str(agent.get("id", ""))
    src_ip   = str(data.get("srcip", data.get("src_ip", data.get("srcIP", ""))))
    minute   = raw_ts[:16] if len(raw_ts) >= 16 else raw_ts
    raw      = f"{rule_id}|{agent_id}|{src_ip}|{minute}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def deduplicate_alerts(alerts: list[dict]) -> tuple[list[dict], int]:
    seen: set[str] = set()
    unique: list[dict] = []
    dupes = 0
    for alert in alerts:
        fp = _alert_fingerprint(alert)
        if fp in seen:
            dupes += 1
        else:
            seen.add(fp)
            unique.append(alert)
    return unique, dupes


# ──────────────────────────────────────────────
# Alert reader & filter
# ──────────────────────────────────────────────

def read_alerts_from_file(filepath: str) -> list[dict]:
    alerts: list[dict] = []
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
                alerts.append(json.loads(line))
            except json.JSONDecodeError as e:
                logger.warning(f"Skipping malformed JSON line: {e}")
    return alerts


def _is_custom_rule(rule_id) -> bool:
    try:
        return CUSTOM_RULE_MIN <= int(rule_id) <= CUSTOM_RULE_MAX
    except (ValueError, TypeError):
        return False


def filter_alerts(alerts: list[dict], threshold: int = ALERT_LEVEL_THRESHOLD) -> list[dict]:
    selected: list[dict] = []
    for alert in alerts:
        rule    = alert.get("rule", {})
        rule_id = rule.get("id", 0)
        try:
            level = int(rule.get("level", 0))
        except (ValueError, TypeError):
            level = 0
        if level > threshold or _is_custom_rule(rule_id):
            selected.append(alert)
    return selected


def tail_new_alerts(filepath: str, last_position: int) -> tuple[list[dict], int]:
    alerts: list[dict] = []
    path = Path(filepath)
    if not path.exists():
        return alerts, last_position
    with open(filepath, "r", encoding="utf-8") as fh:
        fh.seek(last_position)
        for line in fh:
            s = line.strip()
            if s:
                try:
                    alerts.append(json.loads(s))
                except json.JSONDecodeError:
                    pass
        new_position = fh.tell()
    return alerts, new_position


# ──────────────────────────────────────────────
# Claude AI analysis
# ──────────────────────────────────────────────

def build_analysis_prompt(alert: dict) -> str:
    rule      = alert.get("rule", {})
    agent     = alert.get("agent", {})
    data      = alert.get("data", {})
    timestamp = alert.get("timestamp", "unknown")
    rule_id   = rule.get("id", "N/A")
    custom_note = (
        f"  ⚠️  Custom rule ({rule_id}) — organisation-defined detection"
        if _is_custom_rule(rule_id) else ""
    )

    return f"""You are a senior cybersecurity analyst. Analyse the following Wazuh security alert and provide a concise but thorough investigation report.

## Alert Details
- **Timestamp**: {timestamp}
- **Rule ID**: {rule_id}{custom_note}
- **Rule Level**: {rule.get("level", "N/A")} (scale 0–15, critical threshold >{ALERT_LEVEL_THRESHOLD})
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

Please provide your response in this EXACT structure (used for dashboard indexing):

THREAT_SUMMARY: <2-3 sentence summary of what happened and why it is critical>
ATTACK_VECTOR: <How the attacker likely executed this; reference MITRE ATT&CK if applicable>
AFFECTED_ASSETS: <Which systems/services are at risk>
SEVERITY_ASSESSMENT: <Confirm or refine the severity level with reasoning>
IMMEDIATE_ACTIONS: <Top 3-5 containment/remediation steps, pipe-separated>
INVESTIGATION_CHECKLIST: <Additional log sources or indicators to examine, pipe-separated>
FALSE_POSITIVE_LIKELIHOOD: <Low|Medium|High — with one sentence of reasoning>

Keep the report actionable and prioritised for a SOC analyst who must respond within minutes.
"""


def _parse_structured_analysis(text: str) -> dict:
    """
    Parse the structured Claude response into a dict for OpenSearch indexing.
    Falls back gracefully if a field is missing.
    """
    fields = [
        "THREAT_SUMMARY",
        "ATTACK_VECTOR",
        "AFFECTED_ASSETS",
        "SEVERITY_ASSESSMENT",
        "IMMEDIATE_ACTIONS",
        "INVESTIGATION_CHECKLIST",
        "FALSE_POSITIVE_LIKELIHOOD",
    ]
    result: dict[str, str] = {}
    for i, field in enumerate(fields):
        # Match from this field label up to the next one (or end of string)
        next_field = fields[i + 1] if i + 1 < len(fields) else None
        if next_field:
            import re
            pattern = rf"{field}:\s*(.*?)(?={next_field}:)"
        else:
            import re
            pattern = rf"{field}:\s*(.*)"
        match = re.search(pattern, text, re.DOTALL)
        result[field.lower()] = match.group(1).strip() if match else ""
    return result


def analyze_alert_with_claude(alert: dict, client: anthropic.Anthropic) -> tuple[str, dict]:
    """
    Send alert to Claude. Returns (raw_text, parsed_fields_dict).
    """
    prompt = build_analysis_prompt(alert)
    try:
        message = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=CLAUDE_MAX_TOKENS,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = message.content[0].text
        parsed = _parse_structured_analysis(raw)
        return raw, parsed
    except anthropic.APIConnectionError as e:
        err = f"[ERROR] Could not connect to Claude API: {e}"
        return err, {}
    except anthropic.RateLimitError:
        err = "[ERROR] Claude API rate limit reached. Retry later."
        return err, {}
    except anthropic.APIStatusError as e:
        err = f"[ERROR] Claude API error {e.status_code}: {e.message}"
        return err, {}


# ──────────────────────────────────────────────
# OpenSearch JSON writer  (NEW in V3)
# ──────────────────────────────────────────────

def write_opensearch_event(
    alert: dict,
    parsed: dict,
    raw_analysis: str,
    output_file: str,
) -> None:
    """
    Append a single newline-delimited JSON event to the OpenSearch feed file.

    The event schema maps cleanly to Wazuh dashboard fields:
      rule.id        → shown as "Rule ID"   in Security Events
      rule.level     → shown as "Rule Level"
      agent.name/ip  → shown in Agents panel
      claude.*       → custom fields visible in Discover / dashboards

    Filebeat is configured (see README below) to ship this file to
    Logstash, which forwards it to the wazuh-claude-* index.
    """
    rule  = alert.get("rule", {})
    agent = alert.get("agent", {})

    # Parse false-positive likelihood into a numeric score for easy visualisation
    fpl_text = parsed.get("false_positive_likelihood", "").lower()
    fpl_score = 3 if "high" in fpl_text else (2 if "medium" in fpl_text else 1)

    event = {
        # ── Timestamp (ISO-8601, UTC) ──────────────────────────
        "@timestamp": datetime.now(timezone.utc).isoformat(),

        # ── Wazuh-compatible rule block ────────────────────────
        "rule": {
            "id":          str(rule.get("id", "")),
            "level":       int(rule.get("level", 0)),
            "description": rule.get("description", ""),
            "groups":      rule.get("groups", []),
            "mitre":       rule.get("mitre", {}),
            "is_custom":   _is_custom_rule(rule.get("id", 0)),
        },

        # ── Agent block ────────────────────────────────────────
        "agent": {
            "id":   agent.get("id", ""),
            "name": agent.get("name", ""),
            "ip":   agent.get("ip", ""),
        },

        # ── Claude analysis fields (custom namespace) ──────────
        "claude": {
            "threat_summary":          parsed.get("threat_summary", ""),
            "attack_vector":           parsed.get("attack_vector", ""),
            "affected_assets":         parsed.get("affected_assets", ""),
            "severity_assessment":     parsed.get("severity_assessment", ""),
            "immediate_actions":       parsed.get("immediate_actions", "").split("|"),
            "investigation_checklist": parsed.get("investigation_checklist", "").split("|"),
            "false_positive_likelihood": {
                "label": parsed.get("false_positive_likelihood", ""),
                "score": fpl_score,   # 1=Low 2=Medium 3=High  (useful for charts)
            },
            "raw_analysis": raw_analysis,
            "model":        CLAUDE_MODEL,
        },

        # ── Original alert preserved verbatim ─────────────────
        "original_alert": alert,
    }

    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(event) + "\n")

    logger.info(f"📊  OpenSearch event written → {output_file}")


# ──────────────────────────────────────────────
# Text report (kept from V2)
# ──────────────────────────────────────────────

def save_text_report(alert: dict, analysis: str, output_dir: str) -> str:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    rule       = alert.get("rule", {})
    rule_id    = rule.get("id", "unknown")
    level      = rule.get("level", "unknown")
    custom_tag = "_CUSTOM" if _is_custom_rule(rule_id) else ""
    ts         = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename   = f"alert_L{level}_rule{rule_id}{custom_tag}_{ts}.txt"
    filepath   = Path(output_dir) / filename

    lines = [
        "=" * 70,
        "WAZUH ALERT — CLAUDE AI SECURITY ANALYSIS  (V3)",
        "=" * 70,
        f"Generated   : {datetime.now(timezone.utc).isoformat()}",
        f"Rule ID     : {rule_id}" + (" [CUSTOM 6-DIGIT RULE]" if _is_custom_rule(rule_id) else ""),
        f"Rule Level  : {level}",
        f"Description : {rule.get('description', 'N/A')}",
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
    filepath.write_text("\n".join(lines), encoding="utf-8")
    return str(filepath)


def print_report(alert: dict, analysis: str, report_path: str):
    rule       = alert.get("rule", {})
    rule_id    = rule.get("id", "?")
    custom_tag = "  🔧 [CUSTOM RULE]" if _is_custom_rule(rule_id) else ""
    print("\n" + "=" * 70)
    print("🔴  WAZUH ALERT — CLAUDE AI INVESTIGATION  (V3)")
    print("=" * 70)
    print(f"  Rule ID    : {rule_id}{custom_tag}")
    print(f"  Level      : {rule.get('level')}  (threshold >{ALERT_LEVEL_THRESHOLD})")
    print(f"  Description: {rule.get('description')}")
    print(f"  Agent      : {alert.get('agent', {}).get('name')}  "
          f"({alert.get('agent', {}).get('ip')})")
    print("-" * 70)
    print("🤖  CLAUDE ANALYSIS")
    print("-" * 70)
    print(analysis)
    print("-" * 70)
    print(f"📄  Text report  → {report_path}")
    print(f"📊  OpenSearch   → {OPENSEARCH_JSON_FILE}")
    print("=" * 70 + "\n")


# ──────────────────────────────────────────────
# Main modes
# ──────────────────────────────────────────────

def _process_alert(alert: dict, client: anthropic.Anthropic, write_os: bool):
    raw, parsed   = analyze_alert_with_claude(alert, client)
    report_path   = save_text_report(alert, raw, OUTPUT_DIR)
    if write_os:
        write_opensearch_event(alert, parsed, raw, OPENSEARCH_JSON_FILE)
    print_report(alert, raw, report_path)


def run_once(alert_file: str, client: anthropic.Anthropic, write_os: bool):
    logger.info(f"Reading alerts from: {alert_file}")
    raw_alerts        = read_alerts_from_file(alert_file)
    matched           = filter_alerts(raw_alerts)
    unique, dupes     = deduplicate_alerts(matched)

    if not unique:
        logger.info("No qualifying alerts found.")
        return

    logger.info(
        f"Matched {len(matched)} → {len(unique)} unique "
        f"({dupes} duplicate(s) suppressed)."
    )

    for i, alert in enumerate(unique, 1):
        rid   = alert.get("rule", {}).get("id", "?")
        level = alert.get("rule", {}).get("level", "?")
        desc  = alert.get("rule", {}).get("description", "?")
        tag   = " [CUSTOM]" if _is_custom_rule(rid) else ""
        logger.info(f"[{i}/{len(unique)}] level-{level} rule-{rid}{tag}: {desc}")
        _process_alert(alert, client, write_os)

    logger.info(
        f"✅  Done. {len(unique)} report(s) written. "
        f"OpenSearch feed: {OPENSEARCH_JSON_FILE}"
    )


def run_watch(alert_file: str, client: anthropic.Anthropic,
              write_os: bool, dedup_window: int = DEDUP_WINDOW_SECONDS):
    logger.info(f"👀  Watch mode — tailing {alert_file}  (poll every {POLL_INTERVAL}s)")

    path     = Path(alert_file)
    position = path.stat().st_size if path.exists() else 0
    seen: dict[str, float] = {}

    try:
        while True:
            now     = time.time()
            expired = [fp for fp, ts in seen.items() if now - ts > dedup_window]
            for fp in expired:
                del seen[fp]

            new_alerts, position = tail_new_alerts(alert_file, position)
            for alert in filter_alerts(new_alerts):
                fp = _alert_fingerprint(alert)
                if fp in seen:
                    continue
                seen[fp] = now
                rid   = alert.get("rule", {}).get("id", "?")
                level = alert.get("rule", {}).get("level", "?")
                tag   = " [CUSTOM]" if _is_custom_rule(rid) else ""
                logger.info(f"🔴 New level-{level} rule-{rid}{tag}")
                _process_alert(alert, client, write_os)

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        logger.info("Watch mode stopped by user.")


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def main():
    global ALERT_LEVEL_THRESHOLD

    parser = argparse.ArgumentParser(
        description="Wazuh Alert Analyzer with Claude AI — V3 (dashboard integration)"
    )
    parser.add_argument("--mode", choices=["once", "watch"], default="once")
    parser.add_argument("--alerts-file", default=WAZUH_ALERTS_JSON)
    parser.add_argument("--level", type=int, default=ALERT_LEVEL_THRESHOLD,
        help="Analyse alerts ABOVE this level (6-digit custom rules always included)")
    parser.add_argument("--dedup-window", type=int, default=DEDUP_WINDOW_SECONDS,
        help=f"Watch-mode dedup window in seconds (default: {DEDUP_WINDOW_SECONDS})")
    parser.add_argument("--no-opensearch", action="store_true",
        help="Skip writing the OpenSearch JSON feed (text reports only)")
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        logger.error("ANTHROPIC_API_KEY environment variable is not set.")
        logger.error("Export it: export ANTHROPIC_API_KEY='sk-ant-...'")
        sys.exit(1)

    ALERT_LEVEL_THRESHOLD = args.level
    write_os = not args.no_opensearch
    client   = anthropic.Anthropic(api_key=api_key)

    logger.info(f"Claude model   : {CLAUDE_MODEL}")
    logger.info(f"Alert filter   : level > {ALERT_LEVEL_THRESHOLD} OR 6-digit custom rule")
    logger.info(f"OpenSearch feed: {'enabled → ' + OPENSEARCH_JSON_FILE if write_os else 'disabled'}")

    if args.mode == "watch":
        run_watch(args.alerts_file, client, write_os, args.dedup_window)
    else:
        run_once(args.alerts_file, client, write_os)


if __name__ == "__main__":
    main()
