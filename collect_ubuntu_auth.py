#!/usr/bin/env python3

"""
collect_ubuntu_auth.py

Purpose:
Collect Ubuntu authentication logs for a specific time period.

This version reads:
- /var/log/auth.log
- /var/log/auth.log.1
- compressed rotated files like /var/log/auth.log.2.gz

This is useful because older logs may be moved into rotated log files.

Safety:
- This script only reads log files.
- It does not delete, edit, or modify system logs.
- It writes matching lines into collected_logs/ubuntu_auth_collected.log
"""

import gzip
from datetime import datetime
from pathlib import Path


# All Ubuntu authentication log files, including rotated logs.
LOG_FILES = sorted(Path("/var/log").glob("auth.log*"))

# Folder where project-collected logs will be stored.
OUTPUT_DIR = Path("collected_logs")

# Output file for collected Ubuntu authentication logs.
OUTPUT_FILE = OUTPUT_DIR / "ubuntu_auth_collected.log"


def open_log_file(log_path):
    """
    Open normal text logs and compressed .gz logs safely.

    Normal files:
    /var/log/auth.log
    /var/log/auth.log.1

    Compressed files:
    /var/log/auth.log.2.gz
    """
    if log_path.suffix == ".gz":
        return gzip.open(log_path, "rt", encoding="utf-8", errors="replace")

    return log_path.open("r", encoding="utf-8", errors="replace")


def parse_ubuntu_timestamp(line):
    """
    Extract and convert the timestamp from an Ubuntu auth.log line.

    Example from your Ubuntu:
    2026-04-22T15:18:39.759433+05:30 SOC101-Ubuntu sudo: ...

    The timestamp is the first part of the line before the first space.
    """
    try:
        timestamp_text = line.split(" ", 1)[0]
        return datetime.fromisoformat(timestamp_text)
    except (IndexError, ValueError):
        return None


def collect_logs(start_time, end_time):
    """
    Read all auth.log files and collect lines between start_time and end_time.
    """
    collected_lines = []

    if not LOG_FILES:
        print("ERROR: No auth.log files found in /var/log/")
        return collected_lines

    print("Reading these log files:")
    for log_file in LOG_FILES:
        print(f"- {log_file}")
    print()

    for log_file in LOG_FILES:
        try:
            with open_log_file(log_file) as file:
                for line in file:
                    log_time = parse_ubuntu_timestamp(line)

                    # Skip lines where timestamp cannot be understood.
                    if log_time is None:
                        continue

                    if start_time <= log_time <= end_time:
                        collected_lines.append(line)

        except PermissionError:
            print(f"ERROR: Permission denied for {log_file}")
            print("Run this script using sudo.")
        except OSError as error:
            print(f"WARNING: Could not read {log_file}: {error}")

    return collected_lines


def main():
    """
    Ask the user for a start and end time, then collect matching logs.
    """
    print("Ubuntu Auth Log Collector")
    print("Time format example: 2026-04-22T00:00:00+05:30")
    print()

    start_text = input("Enter start time: ").strip()
    end_text = input("Enter end time: ").strip()

    try:
        start_time = datetime.fromisoformat(start_text)
        end_time = datetime.fromisoformat(end_text)
    except ValueError:
        print("ERROR: Invalid time format.")
        print("Use format like: 2026-04-22T00:00:00+05:30")
        return

    if start_time > end_time:
        print("ERROR: Start time must be before end time.")
        return

    OUTPUT_DIR.mkdir(exist_ok=True)

    collected_lines = collect_logs(start_time, end_time)

    with OUTPUT_FILE.open("w", encoding="utf-8") as output_file:
        output_file.writelines(collected_lines)

    print("Collection complete.")
    print(f"Lines collected: {len(collected_lines)}")
    print(f"Output saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()