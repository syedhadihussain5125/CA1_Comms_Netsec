"""
app.py  —  Larkspur AI Security Alert Dashboard
Student: Syed Hadi Hussain  |  Module: B9CY110  |  CA1

Streamlit web application that:
  1. Reads Wazuh alerts.json (last N high-severity alerts)
  2. Calls local Ollama API to produce an analyst-grade summary per alert
  3. Displays alerts + summaries in a SOC-style dashboard

DESIGN CONSTRAINTS (per assignment Part D):
  - The AI is strictly READ-ONLY — it produces text summaries only
  - It cannot execute commands, call APIs, or trigger any remediation
  - All actual remediation is done by Wazuh active-response scripts
  - This design is consistent with NIST SP 800-61 Rev 2 guidance
"""

import os
import json
import time
import requests
import streamlit as st
import pandas as pd
from datetime import datetime

# ---- Configuration (from environment or defaults) ---------------------------
OLLAMA_URL      = os.getenv("OLLAMA_URL",        "http://ollama:11434")
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL",       "llama3.2:1b")
ALERTS_JSON     = os.getenv("ALERTS_JSON",        "/var/ossec/logs/alerts/alerts.json")
MIN_LEVEL       = int(os.getenv("MIN_ALERT_LEVEL", "10"))
MAX_ALERTS      = int(os.getenv("MAX_ALERTS_DISPLAY", "50"))

# ---- Page configuration -----------------------------------------------------
st.set_page_config(
    page_title="Larkspur SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---- Sidebar ----------------------------------------------------------------
with st.sidebar:
    st.markdown("### LRG SOC")
    st.title("Larkspur Retail Group")
    st.subheader("AI Security Dashboard")
    st.caption("CA1 — B9CY110 — Syed Hadi Hussain")
    st.divider()

    min_level_filter = st.slider("Minimum Alert Level", 1, 15, MIN_LEVEL)
    max_show = st.slider("Alerts to Show", 5, MAX_ALERTS, 20)
    auto_refresh = st.toggle("Auto-refresh (30s)", value=False)
    summarise_btn = st.button("Summarise Selected Alert", type="primary")
    st.divider()
    st.caption("⚠️ AI is read-only. Remediation is handled by Wazuh active-response.")

# ---- Helper: read alerts from Wazuh JSON log --------------------------------
@st.cache_data(ttl=15)
def read_alerts(path: str, min_level: int, max_n: int) -> list[dict]:
    """
    Reads the Wazuh alerts.json file (one JSON object per line, JSONL format).
    Returns the last max_n alerts at or above min_level, newest first.
    """
    if not os.path.exists(path):
        return []

    alerts = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = json.loads(line)
                    level = alert.get("rule", {}).get("level", 0)
                    if level >= min_level:
                        alerts.append(alert)
                except json.JSONDecodeError:
                    pass
    except PermissionError:
        st.error("Cannot read alerts.json — check volume mount permissions.")

    # Return the most recent max_n alerts, newest first
    return alerts[-max_n:][::-1]


def format_timestamp(ts: str) -> str:
    """Format Wazuh ISO timestamp to a readable string."""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return ts


def severity_badge(level: int) -> str:
    if level >= 13:   return "🔴 CRITICAL"
    elif level >= 10: return "🟠 HIGH"
    elif level >= 7:  return "🟡 MEDIUM"
    else:             return "🟢 LOW"


# ---- Helper: call Ollama API ------------------------------------------------
def summarise_alert(alert: dict) -> str:
    """
    Sends the alert JSON to Ollama and returns an analyst-grade summary.
    The prompt explicitly instructs the model NOT to suggest executing commands.
    """
    rule_id    = alert.get("rule", {}).get("id", "?")
    rule_desc  = alert.get("rule", {}).get("description", "Unknown alert")
    level      = alert.get("rule", {}).get("level", 0)
    agent_name = alert.get("agent", {}).get("name", "unknown")
    timestamp  = format_timestamp(alert.get("timestamp", ""))
    mitre      = alert.get("rule", {}).get("mitre", {}).get("id", ["?"])

    # Keep alert payload compact to fit small-context model
    compact = {
        "rule_id":    rule_id,
        "rule_desc":  rule_desc,
        "level":      level,
        "agent":      agent_name,
        "timestamp":  timestamp,
        "mitre":      mitre,
        "data":       alert.get("data", {}),
    }

    prompt = f"""You are a senior SOC analyst writing a triage note. Analyse this Wazuh security alert and write a concise 3-part summary:

Alert data:
{json.dumps(compact, indent=2)}

Write your response in exactly this format (no extra text):

ANALYST SUMMARY: <2-sentence description of what happened and why it is suspicious>
BUSINESS IMPACT: <1-sentence assessment of potential impact to Larkspur Retail Group>
RECOMMENDED ACTION: <1-sentence next step for the analyst — investigation or containment — do NOT suggest running shell commands directly>
"""

    try:
        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model":  OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.3, "num_ctx": 2048},
            },
            timeout=45,
        )
        if response.status_code == 200:
            return response.json().get("response", "Summary unavailable.").strip()
        return f"Ollama API error: HTTP {response.status_code}"
    except requests.exceptions.ConnectionError:
        return "⚠️ Ollama service is not reachable. Ensure the ollama container is running."
    except requests.exceptions.Timeout:
        return "⚠️ Ollama timed out. The model may still be loading."
    except Exception as exc:
        return f"⚠️ Unexpected error: {exc}"


def check_ollama_health() -> bool:
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
        return r.status_code == 200
    except Exception:
        return False


# ---- Main dashboard ---------------------------------------------------------
st.title("🛡️ Larkspur Retail Group — Security Operations Centre")
st.caption(f"SIEM: Wazuh  |  AI: Ollama ({OLLAMA_MODEL})  |  Alerts file: {ALERTS_JSON}")

# Status row
col1, col2, col3 = st.columns(3)
ollama_ok = check_ollama_health()
col1.metric("Ollama Status", "✅ Online" if ollama_ok else "❌ Offline")
col2.metric("AI Model", OLLAMA_MODEL)
col3.metric("Min Alert Level", min_level_filter)

st.divider()

# Load alerts
with st.spinner("Loading alerts from Wazuh..."):
    alerts = read_alerts(ALERTS_JSON, min_level_filter, max_show)

if not alerts:
    st.info(f"No alerts found at level ≥ {min_level_filter}. "
            f"Ensure Wazuh agents are running and alerts.json is mounted correctly.")
    st.stop()

st.subheader(f"Recent Alerts — {len(alerts)} shown (level ≥ {min_level_filter})")

# Build summary table
rows = []
for i, a in enumerate(alerts):
    rows.append({
        "#":         i + 1,
        "Time":      format_timestamp(a.get("timestamp", "")),
        "Level":     a.get("rule", {}).get("level", 0),
        "Severity":  severity_badge(a.get("rule", {}).get("level", 0)),
        "Agent":     a.get("agent", {}).get("name", "?"),
        "Rule ID":   a.get("rule", {}).get("id", "?"),
        "Description": a.get("rule", {}).get("description", "?"),
        "ATT&CK":    ", ".join(a.get("rule", {}).get("mitre", {}).get("id", ["-"])),
    })

df = pd.DataFrame(rows)
event = st.dataframe(
    df,
    use_container_width=True,
    hide_index=True,
    on_select="rerun",
    selection_mode="single-row",
)

# ---- Alert detail + AI summary panel ----------------------------------------
selected_rows = event.selection.get("rows", []) if hasattr(event, "selection") else []
selected_idx  = selected_rows[0] if selected_rows else 0
selected_alert = alerts[selected_idx]

st.divider()
st.subheader(f"Alert Detail — Rule {selected_alert.get('rule', {}).get('id', '?')}")

detail_col, ai_col = st.columns([1, 1])

with detail_col:
    st.markdown("**Raw Alert Data**")
    st.json(selected_alert, expanded=False)

with ai_col:
    st.markdown("**AI Analyst Summary**")
    st.caption("⚠️ AI output is advisory only — verify before acting.")

    if summarise_btn or st.button("Generate AI Summary", key="gen_btn"):
        if not ollama_ok:
            st.error("Ollama is offline. Start it with: docker compose up -d ollama")
        else:
            with st.spinner(f"Generating summary with {OLLAMA_MODEL}..."):
                summary = summarise_alert(selected_alert)
            # Parse and display the structured summary
            st.markdown("---")
            for line in summary.split("\n"):
                line = line.strip()
                if line.startswith("ANALYST SUMMARY:"):
                    st.info(line)
                elif line.startswith("BUSINESS IMPACT:"):
                    st.warning(line)
                elif line.startswith("RECOMMENDED ACTION:"):
                    st.success(line)
                elif line:
                    st.write(line)

# ---- Detection summary table ------------------------------------------------
st.divider()
st.subheader("Detection Outcomes Summary")
st.caption("MITRE ATT&CK mapping for all fired detections")

mitre_rows = []
for a in alerts:
    rule = a.get("rule", {})
    mitre_ids = rule.get("mitre", {}).get("id", [])
    for mid in (mitre_ids if isinstance(mitre_ids, list) else [mitre_ids]):
        mitre_rows.append({
            "Rule ID":    rule.get("id", "?"),
            "Description": rule.get("description", "?"),
            "Level":      rule.get("level", 0),
            "ATT&CK ID":  mid,
            "Agent":      a.get("agent", {}).get("name", "?"),
        })

if mitre_rows:
    st.dataframe(pd.DataFrame(mitre_rows).drop_duplicates(), use_container_width=True, hide_index=True)

# ---- Auto-refresh -----------------------------------------------------------
if auto_refresh:
    time.sleep(30)
    st.rerun()
