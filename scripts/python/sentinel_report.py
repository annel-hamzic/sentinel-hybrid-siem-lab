#!/usr/bin/env python3
"""
sentinel_report.py - Security summary report from a Microsoft Sentinel workspace.

Queries the Log Analytics workspace behind Microsoft Sentinel with KQL and builds
a report covering:

  1. Data ingestion health   - events per host and table, last event seen
  2. Sentinel incidents      - incidents raised by the analytics rules
  3. Linux SSH failures      - failed SSH logins by source IP, host, and user (Syslog)
  4. Windows logon failures  - failed logons (Event ID 4625) by account and host
  5. Admin group additions   - accounts added to local Administrators (Event ID 4732)

The report prints to the console and is saved as a Markdown file, ready to
commit or attach to a ticket.

Authentication uses DefaultAzureCredential: run `az login` first, or let the
script open a browser sign-in. No secrets are stored in this file.

Usage:
    export SENTINEL_WORKSPACE_ID="<Log Analytics workspace ID>"
    python sentinel_report.py                 # last 24 hours
    python sentinel_report.py --hours 72      # last 3 days
    python sentinel_report.py --output-dir reports --no-file
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    from dotenv import load_dotenv
except ImportError:  # python-dotenv is optional
    load_dotenv = None


# ---------------------------------------------------------------------------
# KQL queries - one per report section. {limit} is filled in at runtime.
# The time window is applied by the API (timespan), not inside the query.
# ---------------------------------------------------------------------------

@dataclass
class Section:
    key: str
    title: str
    description: str
    query: str
    empty_message: str = "No matching events in this time window."


SECTIONS: list[Section] = [
    Section(
        key="ingestion",
        title="Data Ingestion Health",
        description="Events received per host and table. A host missing here "
                    "means its agent or data collection rule is not sending logs.",
        query="""
union withsource=SourceTable SecurityEvent, Syslog
| summarize Events = count(), LastSeen = max(TimeGenerated) by Computer, SourceTable
| extend MinutesSinceLastEvent = datetime_diff('minute', now(), LastSeen)
| order by Computer asc, SourceTable asc
""",
        empty_message="No SecurityEvent or Syslog data received. Check the agents and DCRs.",
    ),
    Section(
        key="incidents",
        title="Sentinel Incidents",
        description="Incidents created by the analytics rules (latest state of each).",
        query="""
SecurityIncident
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| project IncidentNumber, Title, Severity, Status, Classification,
          Created = CreatedTime
| order by IncidentNumber desc
| take {limit}
""",
        empty_message="No incidents were created in this time window.",
    ),
    Section(
        key="ssh_failures",
        title="Linux - Failed SSH Logins",
        description="Failed SSH password attempts grouped by source IP and target host. "
                    "Rows at or above 5 attempts match the SSH brute-force rule threshold.",
        query="""
Syslog
| where Facility in ("auth", "authpriv")
| where SyslogMessage has "Failed password"
| extend SrcIP = extract(@"from (\\d{{1,3}}(?:\\.\\d{{1,3}}){{3}})", 1, SyslogMessage),
         TargetUser = extract(@"for (?:invalid user )?(\\S+) from", 1, SyslogMessage)
| summarize Attempts = count(), TargetUsers = make_set(TargetUser, 10),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by SrcIP, Computer
| extend AboveThreshold = Attempts >= 5
| order by Attempts desc
| take {limit}
""",
    ),
    Section(
        key="windows_failures",
        title="Windows - Failed Logons (Event ID 4625)",
        description="Failed logons grouped by target account and host. "
                    "Rows at or above 5 attempts match the Windows brute-force rule threshold.",
        query="""
SecurityEvent
| where EventID == 4625
| summarize Attempts = count(), LogonTypes = make_set(LogonType, 10),
            SourceIPs = make_set(IpAddress, 10),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by TargetAccount, Computer
| extend AboveThreshold = Attempts >= 5
| order by Attempts desc
| take {limit}
""",
    ),
    Section(
        key="admin_additions",
        title="Windows - Accounts Added to Administrators (Event ID 4732)",
        description="Every addition to the built-in Administrators group "
                    "(SID S-1-5-32-544). Each one should be expected and approved.",
        query="""
SecurityEvent
| where EventID == 4732
| where TargetSid == "S-1-5-32-544"
| project TimeGenerated, Computer, AddedMemberSid = MemberSid,
          AddedBy = SubjectAccount
| order by TimeGenerated desc
| take {limit}
""",
    ),
]


@dataclass
class SectionResult:
    section: Section
    columns: list[str] = field(default_factory=list)
    rows: list[list[Any]] = field(default_factory=list)
    error: str | None = None
    partial: bool = False


# ---------------------------------------------------------------------------
# Querying
# ---------------------------------------------------------------------------

def build_client():
    """Create a LogsQueryClient using the developer's existing Azure sign-in."""
    from azure.identity import DefaultAzureCredential
    from azure.monitor.query import LogsQueryClient

    # Tries environment variables, managed identity, Azure CLI (`az login`),
    # and finally an interactive browser sign-in.
    credential = DefaultAzureCredential(exclude_interactive_browser_credential=False)
    return LogsQueryClient(credential)


def run_section(client, workspace_id: str, section: Section,
                window: timedelta, limit: int) -> SectionResult:
    from azure.core.exceptions import HttpResponseError
    from azure.monitor.query import LogsQueryStatus

    result = SectionResult(section=section)
    query = section.query.format(limit=limit)

    try:
        response = client.query_workspace(workspace_id, query, timespan=window)
    except HttpResponseError as exc:
        result.error = _short_error(exc)
        return result

    if response.status == LogsQueryStatus.PARTIAL:
        result.partial = True
        tables = response.partial_data
    elif response.status == LogsQueryStatus.SUCCESS:
        tables = response.tables
    else:
        result.error = "Query failed with an unknown status."
        return result

    if tables:
        table = tables[0]
        result.columns = list(table.columns)
        result.rows = [list(row) for row in table.rows]
    return result


def _short_error(exc: Exception) -> str:
    message = str(getattr(exc, "message", "") or exc)
    first_line = message.strip().splitlines()[0] if message.strip() else type(exc).__name__
    if "SecurityIncident" in message and "Failed to resolve" in message:
        return "SecurityIncident table not found (no incidents have been created yet)."
    return first_line[:300]


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def format_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    if isinstance(value, bool):
        return "YES" if value else "no"
    if isinstance(value, (list, tuple)):
        return ", ".join(format_value(v) for v in value if v not in (None, "", "-")) or "-"
    text = str(value).replace("|", "\\|").replace("\n", " ")
    return text if len(text) <= 80 else text[:77] + "..."


def markdown_table(columns: list[str], rows: list[list[Any]]) -> str:
    header = "| " + " | ".join(columns) + " |"
    divider = "| " + " | ".join("---" for _ in columns) + " |"
    body = ["| " + " | ".join(format_value(v) for v in row) + " |" for row in rows]
    return "\n".join([header, divider, *body])


def console_table(columns: list[str], rows: list[list[Any]]) -> str:
    cells = [[format_value(v) for v in row] for row in rows]
    widths = [max(len(c), *(len(r[i]) for r in cells)) if cells else len(c)
              for i, c in enumerate(columns)]
    def line(values):
        return "  ".join(v.ljust(widths[i]) for i, v in enumerate(values))
    out = [line(columns), line(["-" * w for w in widths])]
    out += [line(r) for r in cells]
    return "\n".join(out)


def key_findings(results: dict[str, SectionResult]) -> list[str]:
    """Plain-language highlights for the top of the report."""
    findings: list[str] = []

    def rows_of(key):
        r = results.get(key)
        return r.rows if r and not r.error else []

    def col(key, name):
        r = results[key]
        return r.columns.index(name) if name in r.columns else None

    hosts = {row[col("ingestion", "Computer")] for row in rows_of("ingestion")}
    if hosts:
        findings.append(f"{len(hosts)} host(s) sending logs: {', '.join(sorted(hosts))}.")
    else:
        findings.append("No hosts are sending logs in this window.")

    incidents = rows_of("incidents")
    if incidents:
        sev = col("incidents", "Severity")
        high = sum(1 for r in incidents if str(r[sev]).lower() == "high")
        findings.append(f"{len(incidents)} incident(s) recorded, {high} of them High severity.")

    for key, label in (("ssh_failures", "SSH source IP(s)"),
                       ("windows_failures", "Windows account(s)")):
        idx = col(key, "AboveThreshold") if rows_of(key) else None
        flagged = [r for r in rows_of(key) if idx is not None and r[idx]]
        if flagged:
            findings.append(f"{len(flagged)} {label} at or above the brute-force threshold.")

    additions = rows_of("admin_additions")
    if additions:
        findings.append(f"{len(additions)} addition(s) to the Administrators group - verify each was approved.")

    return findings


def build_markdown(results: dict[str, SectionResult], workspace_id: str,
                   hours: int, generated: datetime) -> str:
    lines = [
        "# Microsoft Sentinel Security Report",
        "",
        f"- **Generated:** {generated.strftime('%Y-%m-%d %H:%M UTC')}",
        f"- **Time window:** last {hours} hour(s)",
        f"- **Workspace:** `...{workspace_id[-6:]}`",
        "",
        "## Key Findings",
        "",
        *[f"- {f}" for f in key_findings(results)],
        "",
    ]
    for res in results.values():
        lines += [f"## {res.section.title}", "", f"_{res.section.description}_", ""]
        if res.error:
            lines += [f"> Query error: {res.error}", ""]
            continue
        if res.partial:
            lines += ["> Warning: partial results returned.", ""]
        if res.rows:
            lines += [markdown_table(res.columns, res.rows), ""]
        else:
            lines += [res.section.empty_message, ""]
    return "\n".join(lines)


def print_console(results: dict[str, SectionResult], hours: int) -> None:
    print(f"\n=== Microsoft Sentinel Security Report (last {hours}h) ===\n")
    print("Key findings:")
    for finding in key_findings(results):
        print(f"  - {finding}")
    for res in results.values():
        print(f"\n--- {res.section.title} ---")
        if res.error:
            print(f"  Query error: {res.error}")
        elif res.rows:
            print(console_table(res.columns, res.rows))
        else:
            print(f"  {res.section.empty_message}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a security summary report from a Microsoft Sentinel workspace.")
    parser.add_argument("--workspace-id", default=None,
                        help="Log Analytics workspace ID (or set SENTINEL_WORKSPACE_ID).")
    parser.add_argument("--hours", type=int, default=24,
                        help="How many hours back to report on (default: 24).")
    parser.add_argument("--limit", type=int, default=25,
                        help="Maximum rows per section (default: 25).")
    parser.add_argument("--output-dir", default="reports",
                        help="Folder for the Markdown report (default: reports).")
    parser.add_argument("--no-file", action="store_true",
                        help="Print to the console only; do not write a report file.")
    args = parser.parse_args(argv)
    if not 1 <= args.hours <= 24 * 90:
        parser.error("--hours must be between 1 and 2160 (90 days).")
    if not 1 <= args.limit <= 500:
        parser.error("--limit must be between 1 and 500.")
    return args


def main(argv: list[str] | None = None) -> int:
    if load_dotenv:
        load_dotenv()
    args = parse_args(argv)

    workspace_id = args.workspace_id or os.getenv("SENTINEL_WORKSPACE_ID")
    if not workspace_id:
        print("Error: set SENTINEL_WORKSPACE_ID (or pass --workspace-id). Find it in the "
              "Azure portal: Log Analytics workspaces > law-siem-lab > Overview > Workspace ID.",
              file=sys.stderr)
        return 2

    try:
        client = build_client()
    except ImportError:
        print("Error: missing packages. Run: pip install -r requirements.txt", file=sys.stderr)
        return 2

    window = timedelta(hours=args.hours)
    results: dict[str, SectionResult] = {}
    for section in SECTIONS:
        print(f"Querying: {section.title} ...", file=sys.stderr)
        results[section.key] = run_section(client, workspace_id, section, window, args.limit)

    if all(r.error for r in results.values()):
        first = next(iter(results.values())).error
        print(f"Error: every query failed. First error: {first}\n"
              "Check that you are signed in (az login) and that the workspace ID is correct.",
              file=sys.stderr)
        return 1

    print_console(results, args.hours)

    if not args.no_file:
        generated = datetime.now(timezone.utc)
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"sentinel_report_{generated.strftime('%Y%m%d_%H%M%S')}.md"
        path.write_text(build_markdown(results, workspace_id, args.hours, generated),
                        encoding="utf-8")
        print(f"Report saved to {path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
