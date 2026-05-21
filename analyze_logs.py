#!/usr/bin/env python3

"""
analyze_logs.py

Purpose:
Analyze normalized security logs and create a prioritized incident summary.

Input:
- normalized_logs.csv

Output:
- incident_summary.csv

Expected normalized input columns:
timestamp, source_ip, host, event_type, user, raw_message

This analyzer is designed to be general-purpose for beginner cybersecurity labs.
It does not depend on specific usernames, hostnames, or IP addresses.

Main detection ideas:
- Failed logins
- Repeated failed logins
- Successful login after repeated failures
- Same source IP targeting multiple users
- Same user targeted from multiple source IPs
- Privilege activity after suspicious login
- Failed login followed by privilege activity
- Standalone privilege activity
- Many successful logins from the same source
- Unknown or blank important fields
- Multi-host suspicious activity
- Optional port scan evidence support

Framework examples used:
- NIST CSF
- NIST SP 800-61
- MITRE ATT&CK

Safety:
- This script only reads normalized_logs.csv.
- It does not modify original logs.
- It does not block users.
- It does not change system settings.
"""

import csv
import html
from collections import defaultdict
from pathlib import Path


INPUT_FILE = Path("normalized_logs.csv")
OUTPUT_FILE = Path("incident_summary.csv")
HTML_OUTPUT_FILE = Path("incident_summary.html")


FAILED_MEDIUM_THRESHOLD = 3
FAILED_HIGH_THRESHOLD = 5
PASSWORD_SPRAY_USER_THRESHOLD = 3
MULTI_SOURCE_USER_THRESHOLD = 2
MANY_SUCCESSFUL_LOGINS_THRESHOLD = 10


def read_normalized_logs():
    """
    Read normalized_logs.csv and return all rows as a list.
    """
    rows = []

    if not INPUT_FILE.exists():
        print(f"ERROR: Input file not found: {INPUT_FILE}")
        return rows

    with INPUT_FILE.open("r", encoding="utf-8", errors="replace", newline="") as csv_file:
        reader = csv.DictReader(csv_file)

        for row in reader:
            rows.append(row)

    return rows


def write_incident_summary(incidents):
    """
    Write incident summary rows into incident_summary.csv.
    """
    fieldnames = [
        "timestamp",
        "severity",
        "incident_type",
        "source_ip",
        "host",
        "user",
        "description",
        "evidence_count",
        "recommended_action",
        "framework_mapping",
    ]

    with OUTPUT_FILE.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(incidents)

def count_by_field(rows, field_name):
    """
    Count how many times each value appears in a specific field.
    """
    counts = defaultdict(int)

    for row in rows:
        value = row.get(field_name, "").strip()

        if value:
            counts[value] += 1

    return counts


def get_severity_class(severity):
    """
    Return a CSS class name based on severity.
    """
    severity = severity.lower()

    if severity == "critical":
        return "severity-critical"

    if severity == "high":
        return "severity-high"

    if severity == "medium":
        return "severity-medium"

    return "severity-low"


def get_incidents_by_type(incidents, incident_type):
    """
    Return all incidents that match a specific incident type.
    """
    matching_incidents = []

    for incident in incidents:
        if incident.get("incident_type", "") == incident_type:
            matching_incidents.append(incident)

    return matching_incidents


def make_short_incident_context(matching_incidents):
    """
    Create a short reusable context summary from matching incidents.

    This does not mention lab-specific names like Kali, Ubuntu, Windows,
    student usernames, or fixed IP addresses.
    """
    if not matching_incidents:
        return ""

    source_ips = sorted({
        incident.get("source_ip", "").strip()
        for incident in matching_incidents
        if not is_blank(incident.get("source_ip", ""))
    })

    hosts = sorted({
        incident.get("host", "").strip()
        for incident in matching_incidents
        if not is_blank(incident.get("host", ""))
    })

    users = sorted({
        incident.get("user", "").strip()
        for incident in matching_incidents
        if not is_blank(incident.get("user", ""))
        and incident.get("user", "").strip() not in ["Multiple users", "Multiple sources"]
    })

    evidence_total = 0

    for incident in matching_incidents:
        try:
            evidence_total += int(incident.get("evidence_count", 0))
        except ValueError:
            pass

    context_parts = []

    context_parts.append(f"Matching incidents found: {len(matching_incidents)}")

    if evidence_total:
        context_parts.append(f"Total related evidence rows: {evidence_total}")

    if source_ips:
        context_parts.append(f"Source IPs involved: {', '.join(source_ips[:5])}")

    if hosts:
        context_parts.append(f"Hosts involved: {', '.join(hosts[:5])}")

    if users:
        context_parts.append(f"Users involved: {', '.join(users[:5])}")

    return " | ".join(context_parts)


def build_case_studies(incidents):
    """
    Create reusable case-study explanations based on detected incident types.

    These are generic investigation stories.
    They are not hard-coded to a specific lab, username, hostname, or IP address.
    """
    case_study_templates = [
        {
            "incident_type": "successful_login_after_repeated_failures",
            "title": "Possible Account Compromise",
            "what_happened": (
                "A successful login was detected after repeated failed login attempts "
                "for the same source, host, and user combination."
            ),
            "why_it_matters": (
                "This pattern is important because repeated failures followed by success "
                "may mean that password guessing eventually worked, or that valid credentials "
                "were obtained after several failed attempts."
            ),
            "recommended_action": (
                "Confirm whether the successful login was authorized. Review activity after "
                "the login, reset credentials if suspicious, and preserve related logs."
            ),
        },
        {
            "incident_type": "privilege_activity_after_suspicious_login",
            "title": "Privilege Activity After Suspicious Login",
            "what_happened": (
                "Privilege-related activity was detected for a user who was already linked "
                "to suspicious login activity."
            ),
            "why_it_matters": (
                "This matters because attackers often try to run administrative commands or "
                "access protected resources after gaining access to an account."
            ),
            "recommended_action": (
                "Review the privilege action, confirm whether it was expected, and check for "
                "additional activity by the same account."
            ),
        },
        {
            "incident_type": "windows_repeated_network_failed_logins",
            "title": "Repeated Network Logon Failures",
            "what_happened": (
                "Repeated network-style failed login attempts were detected on a host."
            ),
            "why_it_matters": (
                "This may indicate password guessing against a network service such as file "
                "sharing or remote authentication. It is more suspicious than a single failed login."
            ),
            "recommended_action": (
                "Review the source IP, targeted account, logon type, and whether this network "
                "access was expected."
            ),
        },
        {
            "incident_type": "possible_password_spraying",
            "title": "Possible Password Spraying",
            "what_happened": (
                "The same source IP attempted failed logins against multiple user accounts "
                "on the same host."
            ),
            "why_it_matters": (
                "This can indicate password spraying, where an attacker tries common passwords "
                "against many accounts instead of repeatedly attacking only one account."
            ),
            "recommended_action": (
                "Review all targeted accounts, check password policy, and consider account "
                "lockout, rate limiting, or additional monitoring."
            ),
        },
        {
            "incident_type": "same_user_targeted_from_multiple_sources",
            "title": "Same User Targeted From Multiple Sources",
            "what_happened": (
                "The same user account was targeted by failed login attempts from more than "
                "one source IP."
            ),
            "why_it_matters": (
                "This may indicate distributed password guessing, shared account targeting, "
                "or a wider campaign against a specific user."
            ),
            "recommended_action": (
                "Review the targeted account, check for successful logins, confirm with the "
                "user, and consider a password reset if the activity is suspicious."
            ),
        },
        {
            "incident_type": "many_successful_logins_from_same_source",
            "title": "High Volume of Successful Logins",
            "what_happened": (
                "Many successful logins were detected from the same source IP to the same host."
            ),
            "why_it_matters": (
                "This may be normal in some environments, but it can also indicate automated "
                "access, shared credentials, or unusual remote activity."
            ),
            "recommended_action": (
                "Check whether this login volume is expected. Review session activity, source "
                "system purpose, and account usage."
            ),
        },
        {
            "incident_type": "port_scan_detected",
            "title": "Port Scan Evidence",
            "what_happened": (
                "Port scan evidence was found in the normalized logs."
            ),
            "why_it_matters": (
                "Port scanning can be part of reconnaissance, where someone checks which "
                "services are exposed before attempting access."
            ),
            "recommended_action": (
                "Confirm whether the scan was authorized. Review exposed services and check "
                "for related authentication events from the same source."
            ),
        },
        {
            "incident_type": "multi_host_suspicious_activity",
            "title": "Multi-Host Suspicious Activity",
            "what_happened": (
                "The same source IP was involved in suspicious activity across more than one host."
            ),
            "why_it_matters": (
                "This is important because activity across multiple hosts can indicate a wider "
                "attack path instead of an isolated event."
            ),
            "recommended_action": (
                "Prioritize investigation of the source IP, review related logs from all affected "
                "hosts, and confirm whether the activity was authorized."
            ),
        },
    ]

    case_studies = []

    for template in case_study_templates:
        matching_incidents = get_incidents_by_type(
            incidents,
            template["incident_type"]
        )

        if not matching_incidents:
            continue

        case_study = template.copy()
        case_study["context"] = make_short_incident_context(matching_incidents)
        case_studies.append(case_study)

    return case_studies

def write_html_report(incidents):
    """
    Write a visual HTML report for the incident summary.

    The report is self-contained:
    - no internet required
    - no external JavaScript
    - no external CSS
    """
    severity_counts = count_by_field(incidents, "severity")
    incident_type_counts = count_by_field(incidents, "incident_type")
    case_studies = build_case_studies(incidents)

    total_incidents = len(incidents)
    critical_count = severity_counts.get("Critical", 0)
    high_count = severity_counts.get("High", 0)
    medium_count = severity_counts.get("Medium", 0)
    low_count = severity_counts.get("Low", 0)

    incident_rows_html = ""

    for incident in incidents:
        severity = html.escape(incident.get("severity", ""))
        severity_class = get_severity_class(severity)

        incident_rows_html += f"""
        <tr>
            <td>{html.escape(incident.get("timestamp", ""))}</td>
            <td><span class="badge {severity_class}">{severity}</span></td>
            <td>{html.escape(incident.get("incident_type", ""))}</td>
            <td>{html.escape(incident.get("source_ip", ""))}</td>
            <td>{html.escape(incident.get("host", ""))}</td>
            <td>{html.escape(incident.get("user", ""))}</td>
            <td>{html.escape(incident.get("description", ""))}</td>
            <td>{html.escape(str(incident.get("evidence_count", "")))}</td>
            <td>{html.escape(incident.get("recommended_action", ""))}</td>
        </tr>
        """

    case_studies_html = ""

    if case_studies:
        for case in case_studies:
            case_studies_html += f"""
            <div class="case-card">
                <h3>{html.escape(case["title"])}</h3>
                <p><strong>What happened:</strong> {html.escape(case["what_happened"])}</p>
                <p><strong>Why it matters:</strong> {html.escape(case["why_it_matters"])}</p>
                <p><strong>Detected context:</strong> {html.escape(case["context"])}</p>
                <p><strong>Recommended action:</strong> {html.escape(case["recommended_action"])}</p>
            </div>
            """
    else:
        case_studies_html = """
        <div class="case-card">
            <h3>No Major Investigation Story Detected</h3>
            <p>The analyzer did not find a major suspicious chain such as successful login after repeated failures, password spraying, privilege activity after suspicious login, or multi-host suspicious activity.</p>
        </div>
        """

    incident_type_html = ""

    for incident_type, count in sorted(incident_type_counts.items()):
        incident_type_html += f"""
        <div class="mini-stat">
            <span>{html.escape(incident_type)}</span>
            <strong>{count}</strong>
        </div>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Incident Summary Report</title>
    <style>
        body {{
            margin: 0;
            font-family: Arial, sans-serif;
            background: #f4f7fb;
            color: #1f2937;
        }}

        header {{
            background: linear-gradient(135deg, #111827, #1f2937);
            color: white;
            padding: 32px;
        }}

        header h1 {{
            margin: 0;
            font-size: 30px;
        }}

        header p {{
            margin-top: 8px;
            color: #d1d5db;
            max-width: 900px;
        }}

        main {{
            padding: 30px;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 18px;
            margin-bottom: 30px;
        }}

        .summary-card {{
            background: white;
            border-radius: 14px;
            padding: 20px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.07);
            border-left: 6px solid #2563eb;
        }}

        .summary-card h2 {{
            margin: 0;
            font-size: 14px;
            color: #6b7280;
            text-transform: uppercase;
        }}

        .summary-card p {{
            margin: 8px 0 0;
            font-size: 30px;
            font-weight: bold;
        }}

        .critical-border {{
            border-left-color: #991b1b;
        }}

        .high-border {{
            border-left-color: #dc2626;
        }}

        .medium-border {{
            border-left-color: #d97706;
        }}

        .low-border {{
            border-left-color: #2563eb;
        }}

        section {{
            margin-bottom: 35px;
        }}

        section h2 {{
            font-size: 22px;
            margin-bottom: 15px;
        }}

        .note {{
            background: #eef2ff;
            border-left: 5px solid #4f46e5;
            padding: 16px;
            border-radius: 12px;
            margin-bottom: 24px;
        }}

        .case-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(min(320px, 100%), 1fr));
            gap: 18px;
        }}

        .case-card {{
            background: white;
            border-radius: 14px;
            padding: 20px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.07);
            overflow-wrap: anywhere;
        }}

        .case-card h3 {{
            margin-top: 0;
            color: #111827;
        }}

        .mini-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 12px;
        }}

        .mini-stat {{
            background: white;
            padding: 14px 16px;
            border-radius: 12px;
            display: grid;
            grid-template-columns: 1fr auto;
            align-items: center;
            gap: 12px;
            box-shadow: 0 3px 10px rgba(0, 0, 0, 0.06);
            overflow-wrap: anywhere;
        }}

        .mini-stat span {{
            min-width: 0;
            line-height: 1.4;
        }}

        .mini-stat strong {{
            background: #111827;
            color: white;
            padding: 5px 10px;
            border-radius: 999px;
            min-width: 28px;
            text-align: center;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 14px;
            overflow: hidden;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.07);
        }}

        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
            vertical-align: top;
            font-size: 14px;
        }}

        th {{
            background: #111827;
            color: white;
        }}

        tr:hover {{
            background: #f9fafb;
        }}

        .badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 999px;
            color: white;
            font-size: 12px;
            font-weight: bold;
        }}

        .severity-critical {{
            background: #7f1d1d;
        }}

        .severity-high {{
            background: #dc2626;
        }}

        .severity-medium {{
            background: #d97706;
        }}

        .severity-low {{
            background: #2563eb;
        }}

        .table-wrapper {{
            overflow-x: auto;
        }}

        footer {{
            text-align: center;
            color: #6b7280;
            font-size: 13px;
            padding: 20px;
        }}
    </style>
</head>
<body>
    <header>
        <h1>Security Incident Summary Report</h1>
        <p>
            Generated by the Security Incident Log Analyzer and Alert Prioritizer.
            This report summarizes detected incidents, severity levels, investigation stories,
            and recommended actions.
        </p>
    </header>

    <main>
        <section class="summary-grid">
            <div class="summary-card">
                <h2>Total Incidents</h2>
                <p>{total_incidents}</p>
            </div>

            <div class="summary-card critical-border">
                <h2>Critical</h2>
                <p>{critical_count}</p>
            </div>

            <div class="summary-card high-border">
                <h2>High</h2>
                <p>{high_count}</p>
            </div>

            <div class="summary-card medium-border">
                <h2>Medium</h2>
                <p>{medium_count}</p>
            </div>

            <div class="summary-card low-border">
                <h2>Low</h2>
                <p>{low_count}</p>
            </div>
        </section>

        <section>
            <h2>Detected Case Studies / Investigation Stories</h2>

            <div class="note">
                These case studies are generated from detected incident patterns.
                They are not hard-coded to a specific username, IP address, hostname, or lab machine.
            </div>

            <div class="case-grid">
                {case_studies_html}
            </div>
        </section>

        <section>
            <h2>Incident Type Breakdown</h2>
            <div class="mini-stats">
                {incident_type_html}
            </div>
        </section>

        <section>
            <h2>Prioritized Incident Table</h2>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Severity</th>
                            <th>Incident Type</th>
                            <th>Source IP</th>
                            <th>Host</th>
                            <th>User</th>
                            <th>Description</th>
                            <th>Evidence Count</th>
                            <th>Recommended Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {incident_rows_html}
                    </tbody>
                </table>
            </div>
        </section>
    </main>

    <footer>
        This report is generated from normalized security logs. It does not modify logs, block users, or change system settings.
    </footer>
</body>
</html>
"""

    with HTML_OUTPUT_FILE.open("w", encoding="utf-8") as html_file:
        html_file.write(html_content)

def add_incident(
    incidents,
    timestamp,
    severity,
    incident_type,
    source_ip,
    host,
    user,
    description,
    evidence_count,
    recommended_action,
    framework_mapping,
):
    """
    Add one incident to the incident list.
    """
    incidents.append({
        "timestamp": timestamp,
        "severity": severity,
        "incident_type": incident_type,
        "source_ip": source_ip,
        "host": host,
        "user": user,
        "description": description,
        "evidence_count": evidence_count,
        "recommended_action": recommended_action,
        "framework_mapping": framework_mapping,
    })


def get_key(row):
    """
    Create a grouping key using source IP, host, and user.
    """
    return (
        row.get("source_ip", "").strip(),
        row.get("host", "").strip(),
        row.get("user", "").strip(),
    )


def get_host_user_key(row):
    """
    Create a grouping key using host and user.

    This is useful for privilege logs because privilege activity logs may not
    always include the original source IP.
    """
    return (
        row.get("host", "").strip(),
        row.get("user", "").strip(),
    )


def is_blank(value):
    """
    Check whether a value is empty or unknown.
    """
    if value is None:
        return True

    value = str(value).strip().lower()

    return value in ["", "-", "unknown", "none", "null", "n/a"]

def is_loopback_source(source_ip):
    """
    Check whether the source IP represents the local machine.

    Loopback traffic usually means the system is talking to itself.
    It should not be treated like suspicious remote login activity.
    """
    source_ip = str(source_ip).strip().lower()

    return source_ip in [
        "127.0.0.1",
        "::1",
        "localhost",
    ]

def is_windows_network_logon(row):
    """
    Check if a row appears to be a Windows network logon event.

    Windows SMB/network logons commonly include:
    - Logon Type: 3
    - NTLM
    - NtLmSsp
    """
    raw = row.get("raw_message", "").lower()

    if "logon type:" in raw and "logon type: 3" in raw:
        return True

    if "ntlm" in raw or "ntlmsSP".lower() in raw:
        return True

    return False


def analyze_failed_logins(rows, incidents):
    """
    Rule 1:
    Detect failed login activity.

    Logic:
    - 1 failed login = Low
    - 3 to 4 failed logins = Medium
    - 5 or more failed logins = High

    Returns:
    suspicious_keys = source IP, host, user combinations with repeated failures.
    """
    failed_groups = defaultdict(list)

    for row in rows:
        if row.get("event_type") != "failed_login":
            continue

        source_ip = row.get("source_ip", "").strip()

        if is_loopback_source(source_ip):
            continue    

        failed_groups[get_key(row)].append(row)

    suspicious_keys = set()

    for key, failed_rows in failed_groups.items():
        source_ip, host, user = key
        count = len(failed_rows)
        first_time = failed_rows[0].get("timestamp", "")

        if count == 1:
            severity = "Low"
            incident_type = "single_failed_login"
            description = "Single failed login attempt observed."
            recommended_action = (
                "Review only if repeated later or linked with other suspicious activity."
            )
            framework_mapping = (
                "NIST CSF: DE.CM Security Continuous Monitoring"
            )

        elif count < FAILED_HIGH_THRESHOLD:
            severity = "Medium"
            incident_type = "repeated_failed_logins"
            description = (
                f"{count} failed login attempts observed for the same source, host, and user."
            )
            recommended_action = (
                "Review the source IP and account. Check whether the failures were expected, "
                "and monitor for additional attempts."
            )
            framework_mapping = (
                "NIST CSF: DE.AE Anomalies and Events | "
                "MITRE ATT&CK: T1110 Brute Force"
            )
            suspicious_keys.add(key)

        else:
            severity = "High"
            incident_type = "high_volume_failed_logins"
            description = (
                f"{count} failed login attempts observed for the same source, host, and user."
            )
            recommended_action = (
                "Investigate the source IP and targeted account. Consider password reset, "
                "account lockout review, rate limiting, and preserving logs as evidence."
            )
            framework_mapping = (
                "NIST CSF: DE.AE Anomalies and Events, DE.CM Security Continuous Monitoring | "
                "NIST SP 800-61: Detection and Analysis | "
                "MITRE ATT&CK: T1110 Brute Force"
            )
            suspicious_keys.add(key)

        if count >= FAILED_HIGH_THRESHOLD and any(is_windows_network_logon(row) for row in failed_rows):
            incident_type = "windows_repeated_network_failed_logins"
            description = (
                f"{count} Windows network/SMB-style failed login attempts observed "
                "for the same source, host, and user."
            )
            framework_mapping = (
                "NIST CSF: DE.AE Anomalies and Events, DE.CM Security Continuous Monitoring | "
                "MITRE ATT&CK: T1110 Brute Force, T1021 Remote Services"
            )

        add_incident(
            incidents,
            first_time,
            severity,
            incident_type,
            source_ip,
            host,
            user,
            description,
            count,
            recommended_action,
            framework_mapping,
        )

    return suspicious_keys


def analyze_success_after_failures(rows, incidents, suspicious_keys):
    """
    Rule 2:
    Detect successful login after repeated failed login attempts.

    Logic:
    If the same source IP, host, and user had repeated failures and then
    also has successful login activity, summarize it as one Critical incident.

    Returns:
    compromised_keys = source IP, host, user combinations that look possibly compromised.
    """
    successful_groups = defaultdict(list)

    for row in rows:
        if row.get("event_type") != "successful_login":
            continue
        
        source_ip = row.get("source_ip", "").strip()

        if is_loopback_source(source_ip):
            continue

        successful_groups[get_key(row)].append(row)

    compromised_keys = set()

    for key in suspicious_keys:
        if key not in successful_groups:
            continue

        source_ip, host, user = key
        success_rows = successful_groups[key]
        first_success_time = success_rows[0].get("timestamp", "")

        add_incident(
            incidents,
            first_success_time,
            "Critical",
            "successful_login_after_repeated_failures",
            source_ip,
            host,
            user,
            "A successful login occurred after repeated failed login attempts for the same source, host, and user.",
            len(success_rows),
            (
                "Treat as possible account compromise. Confirm whether the login was authorized, "
                "review user activity after login, reset credentials if suspicious, and preserve related logs."
            ),
            (
                "NIST CSF: DE.AE Anomalies and Events, RS.AN Analysis | "
                "NIST SP 800-61: Detection, Analysis, and Prioritization | "
                "MITRE ATT&CK: T1110 Brute Force, T1078 Valid Accounts"
            ),
        )

        compromised_keys.add(key)

    return compromised_keys


def analyze_password_spraying(rows, incidents):
    """
    Rule 3:
    Detect same source IP targeting multiple users.

    Why:
    One source IP failing against several different users can indicate
    password spraying or account discovery.
    """
    source_host_to_users = defaultdict(set)
    source_host_to_rows = defaultdict(list)

    for row in rows:
        if row.get("event_type") != "failed_login":
            continue

        source_ip = row.get("source_ip", "").strip()
        host = row.get("host", "").strip()
        user = row.get("user", "").strip()

        if is_blank(source_ip) or is_blank(host) or is_blank(user):
            continue

        if is_loopback_source(source_ip):
            continue

        key = (source_ip, host)
        source_host_to_users[key].add(user)
        source_host_to_rows[key].append(row)

    for key, users in source_host_to_users.items():
        if len(users) < PASSWORD_SPRAY_USER_THRESHOLD:
            continue

        source_ip, host = key
        rows_for_key = source_host_to_rows[key]
        first_time = rows_for_key[0].get("timestamp", "")

        add_incident(
            incidents,
            first_time,
            "High",
            "possible_password_spraying",
            source_ip,
            host,
            "Multiple users",
            (
                f"Same source IP targeted {len(users)} different users on the same host: "
                f"{', '.join(sorted(users))}."
            ),
            len(rows_for_key),
            (
                "Investigate whether this is password spraying. Review authentication logs, "
                "check affected accounts, enforce strong passwords, and consider account lockout or rate limiting."
            ),
            (
                "NIST CSF: DE.AE Anomalies and Events, DE.CM Security Continuous Monitoring | "
                "MITRE ATT&CK: T1110.003 Password Spraying"
            ),
        )


def analyze_same_user_multiple_sources(rows, incidents):
    """
    Rule 4:
    Detect same user targeted from multiple source IPs.

    Why:
    The same account being attacked from multiple sources may indicate
    distributed guessing, shared account targeting, or a wider campaign.
    """
    host_user_to_sources = defaultdict(set)
    host_user_to_rows = defaultdict(list)

    for row in rows:
        if row.get("event_type") != "failed_login":
            continue

        source_ip = row.get("source_ip", "").strip()
        host = row.get("host", "").strip()
        user = row.get("user", "").strip()

        if is_blank(source_ip) or is_blank(host) or is_blank(user):
            continue

        if is_loopback_source(source_ip):
            continue

        key = (host, user)
        host_user_to_sources[key].add(source_ip)
        host_user_to_rows[key].append(row)

    for key, sources in host_user_to_sources.items():
        if len(sources) < MULTI_SOURCE_USER_THRESHOLD:
            continue

        host, user = key
        rows_for_key = host_user_to_rows[key]
        first_time = rows_for_key[0].get("timestamp", "")

        add_incident(
            incidents,
            first_time,
            "High",
            "same_user_targeted_from_multiple_sources",
            "Multiple sources",
            host,
            user,
            (
                f"Same user was targeted from {len(sources)} different source IPs: "
                f"{', '.join(sorted(sources))}."
            ),
            len(rows_for_key),
            (
                "Review whether the account is being targeted. Confirm with the user, check for successful logins, "
                "consider password reset, and review remote access exposure."
            ),
            (
                "NIST CSF: DE.AE Anomalies and Events, RS.AN Analysis | "
                "MITRE ATT&CK: T1110 Brute Force"
            ),
        )


def analyze_privilege_activity_after_suspicious_login(rows, incidents, compromised_keys):
    """
    Rule 5:
    Detect privilege activity after suspicious login.

    This does not hardcode usernames.
    It checks whether the same host and user were already involved in a suspicious login chain.
    """
    privilege_groups = defaultdict(list)

    for row in rows:
        if row.get("event_type") != "privilege_activity":
            continue

        key = get_host_user_key(row)
        host, user = key

        if not is_blank(host) and not is_blank(user):
            privilege_groups[key].append(row)

    suspicious_host_user_pairs = set()

    for source_ip, host, user in compromised_keys:
        suspicious_host_user_pairs.add((host, user))

    for key, privilege_rows in privilege_groups.items():
        host, user = key

        if key not in suspicious_host_user_pairs:
            continue
            
        strong_privilege_rows = [
            row for row in privilege_rows
            if "command=" in row.get("raw_message", "").lower()
            or "not in sudoers" in row.get("raw_message", "").lower()
        ]

        if not strong_privilege_rows:
            continue

        privilege_rows = strong_privilege_rows

        first_time = privilege_rows[0].get("timestamp", "")

        add_incident(
            incidents,
            first_time,
            "High",
            "privilege_activity_after_suspicious_login",
            "",
            host,
            user,
            "Privilege-related activity observed after suspicious login activity for the same user and host.",
            len(privilege_rows),
            (
                "Review commands or administrative actions performed by this user. "
                "Check whether privilege use was authorized and preserve command/session evidence."
            ),
            (
                "NIST CSF: DE.CM Security Continuous Monitoring, RS.AN Analysis | "
                "NIST SP 800-61: Detection and Analysis | "
                "MITRE ATT&CK: Privilege Escalation"
            ),
        )


def analyze_failed_login_followed_by_privilege(rows, incidents, suspicious_keys):
    """
    Rule 6:
    Detect failed login activity followed by privilege activity.

    Why:
    Even if the log data does not clearly show a successful login, seeing failed
    login attempts and later privilege activity for the same user and host is suspicious.
    """
    privilege_groups = defaultdict(list)

    for row in rows:
        if row.get("event_type") != "privilege_activity":
            continue

        key = get_host_user_key(row)
        host, user = key

        if not is_blank(host) and not is_blank(user):
            privilege_groups[key].append(row)

    suspicious_host_user_pairs = set()

    for source_ip, host, user in suspicious_keys:
        suspicious_host_user_pairs.add((host, user))

    for key, privilege_rows in privilege_groups.items():
        if key not in suspicious_host_user_pairs:
            continue

        host, user = key
        first_time = privilege_rows[0].get("timestamp", "")

        add_incident(
            incidents,
            first_time,
            "High",
            "failed_login_followed_by_privilege_activity",
            "",
            host,
            user,
            "Privilege activity occurred for a user who also had repeated failed login activity on the same host.",
            len(privilege_rows),
            (
                "Review whether the privilege activity is connected to the failed login attempts. "
                "Confirm the user's actions, inspect command history where appropriate, and preserve logs."
            ),
            (
                "NIST CSF: DE.AE Anomalies and Events, RS.AN Analysis | "
                "NIST SP 800-61: Detection and Analysis | "
                "MITRE ATT&CK: T1110 Brute Force, Privilege Escalation"
            ),
        )


def analyze_standalone_privilege_activity(rows, incidents, already_reported_host_user_pairs):
    """
    Rule 7:
    Detect privilege activity without prior suspicious login context.

    Why:
    Privilege activity is not always bad. But it is important enough to summarize,
    especially in a small lab where reviewing admin/sudo actions is part of detection.
    """
    privilege_groups = defaultdict(list)

    for row in rows:
        if row.get("event_type") != "privilege_activity":
            continue

        key = get_host_user_key(row)
        host, user = key

        if not is_blank(host) and not is_blank(user):
            privilege_groups[key].append(row)

    for key, privilege_rows in privilege_groups.items():
        host, user = key

        if key in already_reported_host_user_pairs:
            continue

        first_time = privilege_rows[0].get("timestamp", "")

        add_incident(
            incidents,
            first_time,
            "Medium",
            "standalone_privilege_activity",
            "",
            host,
            user,
            "Privilege-related activity observed without a detected suspicious login chain.",
            len(privilege_rows),
            (
                "Review whether the privilege action was expected. Check the command or administrative action "
                "and confirm it was performed by an authorized user."
            ),
            (
                "NIST CSF: DE.CM Security Continuous Monitoring | "
                "NIST SP 800-61: Detection and Analysis | "
                "MITRE ATT&CK: Privilege Escalation"
            ),
        )


def analyze_many_successful_logins(rows, incidents):
    """
    Rule 8:
    Detect many successful logins from the same source IP.

    Why:
    A large number of successful logins from one source may be normal in some systems,
    but it can also indicate automated access, shared credentials, or unusual remote activity.

    To reduce noise, this rule requires a non-blank source IP.
    """
    success_groups = defaultdict(list)

    for row in rows:
        if row.get("event_type") != "successful_login":
            continue

        source_ip = row.get("source_ip", "").strip()
        host = row.get("host", "").strip()

        if is_blank(source_ip) or is_blank(host):
            continue

        # Ignore localhost because it usually represents local system activity,
        # not remote suspicious access.
        if is_loopback_source(source_ip):
            continue

        key = (source_ip, host)
        success_groups[key].append(row)

    for key, success_rows in success_groups.items():
        if len(success_rows) < MANY_SUCCESSFUL_LOGINS_THRESHOLD:
            continue

        source_ip, host = key
        first_time = success_rows[0].get("timestamp", "")

        users = sorted({
            row.get("user", "").strip()
            for row in success_rows
            if not is_blank(row.get("user", ""))
        })

        user_text = "Multiple users" if len(users) > 1 else (users[0] if users else "")

        add_incident(
            incidents,
            first_time,
            "Medium",
            "many_successful_logins_from_same_source",
            source_ip,
            host,
            user_text,
            (
                f"{len(success_rows)} successful logins observed from the same source IP to the same host."
            ),
            len(success_rows),
            (
                "Review whether this login volume is expected. Check session activity, source system purpose, "
                "and whether the account usage matches normal behavior."
            ),
            (
                "NIST CSF: DE.AE Anomalies and Events, DE.CM Security Continuous Monitoring | "
                "MITRE ATT&CK: T1078 Valid Accounts"
            ),
        )


def analyze_unknown_or_blank_fields(rows, incidents):
    """
    Rule 9:
    Detect important missing fields in suspicious logs.

    Why:
    Missing source IP or username can reduce investigation quality.
    This rule summarizes data-quality issues instead of creating one incident per bad row.
    """
    issue_groups = defaultdict(list)

    important_event_types = {
        "failed_login",
        "successful_login",
        "privilege_activity",
        "port_scan",
    }

    for row in rows:
        event_type = row.get("event_type", "").strip()

        if event_type not in important_event_types:
            continue

        missing_fields = []

        if is_blank(row.get("host", "")):
            missing_fields.append("host")

        if event_type in ["failed_login", "successful_login"] and is_blank(row.get("source_ip", "")):
            missing_fields.append("source_ip")

        if event_type in ["failed_login", "successful_login", "privilege_activity"] and is_blank(row.get("user", "")):
            missing_fields.append("user")

        if not missing_fields:
            continue

        key = (event_type, ", ".join(sorted(missing_fields)))
        issue_groups[key].append(row)

    for key, issue_rows in issue_groups.items():
        event_type, missing_text = key
        first_time = issue_rows[0].get("timestamp", "")

        add_incident(
            incidents,
            first_time,
            "Low",
            "missing_or_unknown_log_fields",
            "",
            "",
            "",
            (
                f"{len(issue_rows)} {event_type} log row(s) had missing or unknown important field(s): {missing_text}."
            ),
            len(issue_rows),
            (
                "Review the normalizer and original logs. Missing fields may reduce investigation accuracy, "
                "but this is usually a data quality issue rather than a confirmed security incident."
            ),
            (
                "NIST CSF: DE.CM Security Continuous Monitoring | "
                "NIST SP 800-61: Evidence Collection and Analysis"
            ),
        )


def analyze_port_scan_support(rows, incidents):
    """
    Rule 10:
    Optional port scan evidence support.

    This rule only works if normalized_logs.csv contains rows with:
    event_type = port_scan

    This is useful if scan evidence is later added manually or normalized from a scan log.
    The script does not fake port scan detection from authentication logs.
    """
    scan_groups = defaultdict(list)

    for row in rows:
        if row.get("event_type") != "port_scan":
            continue

        source_ip = row.get("source_ip", "").strip()
        host = row.get("host", "").strip()

        if is_blank(source_ip) or is_blank(host):
            continue

        if is_loopback_source(source_ip):
            continue

        key = (source_ip, host)
        scan_groups[key].append(row)

    for key, scan_rows in scan_groups.items():
        source_ip, host = key
        first_time = scan_rows[0].get("timestamp", "")

        add_incident(
            incidents,
            first_time,
            "Medium",
            "port_scan_detected",
            source_ip,
            host,
            "",
            "Port scan evidence was found in the normalized logs.",
            len(scan_rows),
            (
                "Review scan source and target. Confirm whether the scan was authorized. "
                "If unauthorized, check exposed services and related authentication events."
            ),
            (
                "NIST CSF: DE.AE Anomalies and Events, DE.CM Security Continuous Monitoring | "
                "MITRE ATT&CK: T1046 Network Service Discovery"
            ),
        )


def analyze_multi_host_activity(incidents):
    """
    Rule 11:
    Detect whether the same source IP is involved in incidents on multiple hosts.

    Why:
    This is correlation logic. It helps identify activity that may be more serious
    than each event alone.
    """
    source_to_hosts = defaultdict(set)
    source_to_incident_count = defaultdict(int)
    source_to_first_time = {}

    for incident in incidents:
        source_ip = incident.get("source_ip", "").strip()
        host = incident.get("host", "").strip()

        if is_blank(source_ip) or is_blank(host):
            continue

        if host in ["Multiple hosts", "Multiple sources"]:
            continue

        source_to_hosts[source_ip].add(host)
        source_to_incident_count[source_ip] += 1

        if source_ip not in source_to_first_time:
            source_to_first_time[source_ip] = incident.get("timestamp", "")

    correlation_incidents = []

    for source_ip, hosts in source_to_hosts.items():
        if len(hosts) < 2:
            continue

        add_incident(
            correlation_incidents,
            source_to_first_time.get(source_ip, ""),
            "Critical",
            "multi_host_suspicious_activity",
            source_ip,
            "Multiple hosts",
            "",
            (
                f"Same source IP was involved in suspicious activity across {len(hosts)} hosts: "
                f"{', '.join(sorted(hosts))}."
            ),
            source_to_incident_count[source_ip],
            (
                "Prioritize investigation of this source IP. Review all related host logs, "
                "check whether this was authorized testing, and isolate affected systems if compromise is suspected."
            ),
            (
                "NIST CSF: DE.AE Anomalies and Events, RS.AN Analysis | "
                "NIST SP 800-61: Incident Analysis and Prioritization | "
                "MITRE ATT&CK: T1021 Remote Services, T1078 Valid Accounts"
            ),
        )

    incidents.extend(correlation_incidents)


def remove_duplicate_incidents(incidents):
    """
    Remove exact duplicate incidents if two rules accidentally create the same summary.
    """
    seen = set()
    unique_incidents = []

    for incident in incidents:
        key = (
            incident.get("severity", ""),
            incident.get("incident_type", ""),
            incident.get("source_ip", ""),
            incident.get("host", ""),
            incident.get("user", ""),
            incident.get("description", ""),
        )

        if key in seen:
            continue

        seen.add(key)
        unique_incidents.append(incident)

    return unique_incidents


def sort_incidents(incidents):
    """
    Sort incidents by severity first, then timestamp.
    """
    severity_order = {
        "Critical": 1,
        "High": 2,
        "Medium": 3,
        "Low": 4,
    }

    return sorted(
        incidents,
        key=lambda row: (
            severity_order.get(row.get("severity", ""), 99),
            row.get("timestamp", ""),
        )
    )


def analyze_logs(rows):
    """
    Run all analyzer rules.
    """
    incidents = []

    suspicious_keys = analyze_failed_logins(rows, incidents)
    compromised_keys = analyze_success_after_failures(rows, incidents, suspicious_keys)

    analyze_password_spraying(rows, incidents)
    analyze_same_user_multiple_sources(rows, incidents)

    analyze_privilege_activity_after_suspicious_login(rows, incidents, compromised_keys)
    
    """
    This rule is useful, but it can duplicate privilege_activity_after_suspicious_login.
    Keep it disabled for cleaner final incident summaries.
    
    analyze_failed_login_followed_by_privilege(rows, incidents, suspicious_keys)
    """
    

    already_reported_host_user_pairs = set()

    for source_ip, host, user in compromised_keys:
        already_reported_host_user_pairs.add((host, user))

    for source_ip, host, user in suspicious_keys:
        already_reported_host_user_pairs.add((host, user))

    """
    Standalone privilege activity can be useful, but it may include normal admin/setup activity.
    Keep it disabled in the main incident summary to reduce noise.
    
    # analyze_standalone_privilege_activity(rows, incidents, already_reported_host_user_pairs)
    """
    
    analyze_many_successful_logins(rows, incidents)
    """
    Missing fields are data-quality issues, not security incidents.
    They can be reported separately later if needed.
    
    #analyze_unknown_or_blank_fields(rows, incidents)
    """
    analyze_port_scan_support(rows, incidents)

    analyze_multi_host_activity(incidents)

    incidents = remove_duplicate_incidents(incidents)
    incidents = sort_incidents(incidents)

    return incidents


def main():
    """
    Main program flow.
    """
    print("Security Incident Analyzer")
    print("Using expanded general framework-aligned rules.")
    print()

    rows = read_normalized_logs()

    if not rows:
        print("No rows found to analyze.")
        return

    incidents = analyze_logs(rows)
    write_incident_summary(incidents)
    write_html_report(incidents)

    print("Analysis complete.")
    print(f"Normalized rows read: {len(rows)}")
    print(f"Incidents written: {len(incidents)}")
    print(f"Output saved to: {OUTPUT_FILE}")
    print(f"HTML report saved to: {HTML_OUTPUT_FILE}")


if __name__ == "__main__":
    main()