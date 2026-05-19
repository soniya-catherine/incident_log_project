#!/usr/bin/env python3

"""
normalize_logs.py

Purpose:
Convert collected Ubuntu and Windows security logs into one common CSV format.

Input files:
- collected_logs/ubuntu_auth_collected.log
- collected_logs/windows_security_events.csv

Output file:
- normalized_logs.csv

Common output columns:
timestamp, source_ip, host, event_type, user, raw_message

This script is safe because:
- It only reads collected log copies.
- It does not modify original system logs.
- It writes a new normalized CSV file.
"""

import csv
import re
from pathlib import Path


# Input files
UBUNTU_LOG_FILE = Path("collected_logs/ubuntu_auth_collected.log")
WINDOWS_CSV_FILE = Path("collected_logs/windows_security_events.csv")

# Output file
OUTPUT_FILE = Path("normalized_logs.csv")


def get_ubuntu_event_type(message):
    """
    Decide Ubuntu event type using simple keyword checks.
    """
    message_lower = message.lower()

    if "failed password" in message_lower:
        return "failed_login"

    if "accepted password" in message_lower:
        return "successful_login"

    if "sudo:" in message_lower or "user not in sudoers" in message_lower:
        return "privilege_activity"

    return "other"


def get_windows_event_type(event_id):
    """
    Convert Windows Event IDs into simple event types.

    4624 = successful logon
    4625 = failed logon
    """
    if str(event_id) == "4624":
        return "successful_login"

    if str(event_id) == "4625":
        return "failed_login"

    return "other"


def extract_ip_from_text(text):
    """
    Extract the first IPv4 address found in text.
    """
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)

    if ip_match:
        return ip_match.group(0)

    return ""


def extract_ubuntu_user(message):
    """
    Extract username from common Ubuntu authentication messages.
    """
    failed_or_success_match = re.search(
        r"(?:Failed|Accepted) password for (?:invalid user )?(\S+)",
        message
    )

    if failed_or_success_match:
        return failed_or_success_match.group(1)

    sudo_match = re.search(r"sudo:\s+(\S+)\s+:", message)

    if sudo_match:
        return sudo_match.group(1)

    return ""


def extract_windows_failed_account(message):
    """
    Extract the failed account name from Windows Event ID 4625 message.

    The Windows message contains:
    Account For Which Logon Failed:
        Account Name: studentwin

    There are multiple 'Account Name' fields, so we try to read the one
    after 'Account For Which Logon Failed'.
    """
    match = re.search(
        r"Account For Which Logon Failed:.*?Account\s+Name:\s+([^\s]+)",
        message,
        re.IGNORECASE | re.DOTALL
    )

    if match:
        return match.group(1)

    return ""


def extract_windows_success_account(message):
    """
    Extract account name from Windows Event ID 4624 message.

    This keeps the logic simple. If it cannot safely find the account,
    it returns blank.
    """
    match = re.search(
        r"New Logon:.*?Account\s+Name:\s+([^\s]+)",
        message,
        re.IGNORECASE | re.DOTALL
    )

    if match:
        return match.group(1)

    return ""


def parse_ubuntu_line(line):
    """
    Convert one Ubuntu auth log line into a normalized dictionary.
    """
    parts = line.strip().split(" ", 2)

    if len(parts) < 3:
        return None

    timestamp = parts[0]
    host = parts[1]
    message = parts[2]

    event_type = get_ubuntu_event_type(message)

    if event_type == "other":
        return None

    return {
        "timestamp": timestamp,
        "source_ip": extract_ip_from_text(message),
        "host": host,
        "event_type": event_type,
        "user": extract_ubuntu_user(message),
        "raw_message": message,
    }


def normalize_ubuntu_logs():
    """
    Read collected Ubuntu logs and return normalized rows.
    """
    normalized_rows = []

    if not UBUNTU_LOG_FILE.exists():
        print(f"WARNING: Ubuntu log file not found: {UBUNTU_LOG_FILE}")
        return normalized_rows

    with UBUNTU_LOG_FILE.open("r", encoding="utf-8", errors="replace") as file:
        for line in file:
            row = parse_ubuntu_line(line)

            if row is not None:
                normalized_rows.append(row)

    return normalized_rows


def parse_windows_row(row):
    """
    Convert one Windows CSV row into a normalized dictionary.
    """
    event_id = row.get("EventId", "")
    event_type = get_windows_event_type(event_id)

    if event_type == "other":
        return None

    message = row.get("Message", "")

    if event_type == "failed_login":
        user = extract_windows_failed_account(message)
    else:
        user = extract_windows_success_account(message)

    return {
        "timestamp": row.get("TimeCreated", ""),
        "source_ip": extract_ip_from_text(message),
        "host": row.get("Host", ""),
        "event_type": event_type,
        "user": user,
        "raw_message": message,
    }


def normalize_windows_logs():
    """
    Read collected Windows Security CSV and return normalized rows.
    """
    normalized_rows = []

    if not WINDOWS_CSV_FILE.exists():
        print(f"WARNING: Windows CSV file not found: {WINDOWS_CSV_FILE}")
        return normalized_rows

    with WINDOWS_CSV_FILE.open("r", encoding="utf-8-sig", errors="replace", newline="") as csv_file:
        reader = csv.DictReader(csv_file)

        for row in reader:
            normalized_row = parse_windows_row(row)

            if normalized_row is not None:
                normalized_rows.append(normalized_row)

    return normalized_rows


def write_normalized_csv(rows):
    """
    Write normalized rows to normalized_logs.csv.
    """
    fieldnames = [
        "timestamp",
        "source_ip",
        "host",
        "event_type",
        "user",
        "raw_message",
    ]

    with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main():
    """
    Main program flow.
    """
    print("Log Normalizer")
    print("Normalizing Linux and Windows logs.")
    print()

    ubuntu_rows = normalize_ubuntu_logs()
    windows_rows = normalize_windows_logs()

    all_rows = ubuntu_rows + windows_rows
    write_normalized_csv(all_rows)

    print("Normalization complete.")
    print(f"Ubuntu rows: {len(ubuntu_rows)}")
    print(f"Windows rows: {len(windows_rows)}")
    print(f"Total rows written: {len(all_rows)}")
    print(f"Output saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()