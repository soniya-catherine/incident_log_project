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
from collections import defaultdict
from pathlib import Path


INPUT_FILE = Path("normalized_logs.csv")
OUTPUT_FILE = Path("incident_summary.csv")


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
        if row.get("event_type") == "failed_login":
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
        if row.get("event_type") == "successful_login":
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
        if source_ip in ["127.0.0.1", "::1"]:
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

    print("Analysis complete.")
    print(f"Normalized rows read: {len(rows)}")
    print(f"Incidents written: {len(incidents)}")
    print(f"Output saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()