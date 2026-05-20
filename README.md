# Security Incident Log Analyzer and Alert Prioritizer

<img width="1774" height="887" alt="Image" src="https://github.com/user-attachments/assets/4dbeab86-638e-4cd2-8a18-853297347128" />

## Project Overview

**Security Incident Log Analyzer and Alert Prioritizer** is a beginner-friendly cybersecurity project that collects security logs from Ubuntu and Windows, converts them into one common format, analyzes suspicious activity, and creates a prioritized incident summary.

The project is designed for students, small labs, and beginner security analysts who want to understand how raw logs can be turned into useful security findings.

This project does not automatically stop attacks. It helps answer important investigation questions such as:

- What happened?
- When did it happen?
- Which machine was involved?
- Which source IP was involved?
- Which user account was involved?
- How serious is it?
- What should be checked first?
- What action is recommended?
- Which cybersecurity framework category does it relate to?

## Problem Solved

Modern systems generate many security logs. These logs are useful, but they can be difficult to read manually.

A single machine may generate hundreds or thousands of events. Some events are normal, some are suspicious, and some become serious only when they are connected with other events.

For example:

- one failed login may be a normal mistake
- repeated failed logins may show password guessing
- successful login after repeated failures may suggest possible account compromise
- privilege activity after suspicious login may make the incident more serious
- suspicious activity from the same source IP across multiple hosts may suggest a larger incident

This project helps reduce log overload by collecting, normalizing, analyzing, and prioritizing logs using simple and transparent rules.

## Features

- Collects Ubuntu authentication logs for a selected time period
- Reads current and rotated Ubuntu authentication logs
- Collects Windows Security Event Logs for a selected time period
- Supports Windows Event ID 4624 and 4625
- Normalizes Ubuntu and Windows logs into one common CSV format
- Detects suspicious authentication and privilege-related activity
- Prioritizes incidents as Low, Medium, High, or Critical
- Provides recommended actions for each incident
- Maps findings to NIST CSF, NIST SP 800-61, and MITRE ATT&CK
- Keeps raw log messages as evidence
- Uses simple Python and PowerShell scripts
- Designed to be easy to understand, modify, and explain

## Repository Files

```text
incident-log-analyzer/
|
|-- collect_ubuntu_auth.py
|-- collect_windows_security.ps1
|-- normalize_logs.py
|-- analyze_logs.py
|-- README.md
|
|-- collected_logs/
|   |-- README.md
|
|-- example_outputs/
|   |-- ubuntu_auth_collected_example.log
|   |-- windows_security_events_example.csv
|   |-- normalized_logs_example.csv
|   |-- incident_summary_example.csv
|   |-- incident_summary.html
```

> Note: The `collected_logs` folder is included in the repository so users do not need to create it manually.

The `example_outputs` folder contains sample output files generated from the author's VMware lab. These files are included so users can understand what the tool output looks like before running it on their own logs.

## Example Outputs Included in This Repository

This repository includes example output files from a completed VMware lab run.

These files are only examples. When users run the collectors, normalizer, and analyzer on their own machines, their output will depend on their own logs, timestamps, usernames, hostnames, and IP addresses.

> **Sanitization note:** The example output files included in this repository have been sanitized before publishing. Sensitive details and system-specific identifiers have been removed or replaced with safe lab values. These files are provided only to show the expected output format.

### `example_outputs/ubuntu_auth_collected_example.log`

This file contains example Ubuntu authentication log lines collected from the lab Ubuntu machine.

It shows events such as:

- failed SSH login attempts
- repeated SSH failures
- successful SSH login
- sudo or privilege-related activity

### `example_outputs/windows_security_events_example.csv`

This file contains example Windows Security events exported from the lab Windows machine.

It includes Windows Event ID examples such as:

- `4624` for successful logon
- `4625` for failed logon

In the lab, repeated failed SMB login attempts from Kali were recorded as Windows Security Event ID `4625`.

### `example_outputs/normalized_logs_example.csv`

This file contains the combined normalized logs from Ubuntu and Windows.

The normalizer converts different log formats into one common structure:

```text
timestamp, source_ip, host, event_type, user, raw_message
```

This makes it easier for the analyzer to process Linux and Windows logs together.

### `example_outputs/incident_summary_example.csv`

This file contains the final prioritized incident summary generated by the analyzer.

It includes fields such as:

```text
timestamp, severity, incident_type, source_ip, host, user, description, evidence_count, recommended_action, framework_mapping
```

This CSV is the main analysis result.

### `example_outputs/incident_summary.html`

This file contains an HTML version of the final incident summary.

It is useful for viewing the analyzer results in a browser or including a cleaner results screenshot in documentation.


## Installation and Setup

### 1. Clone the Repository on Ubuntu

Open a terminal on Ubuntu and run:

```bash
git clone https://github.com/soniya-catherine/incident_log_project.git
cd incident_log_project
```

Check that Python 3 is installed:

```bash
python3 --version
```

If Python 3 is not installed, install it using:

```bash
sudo apt update
sudo apt install python3 -y
```

### 2. Clone the Repository on Windows

Open PowerShell on Windows and run:

```powershell
git clone https://github.com/soniya-catherine/incident_log_project.git
cd incident_log_project
```

If Git is not installed on Windows, install Git first and then run the commands again.

Git download page:

```text
https://git-scm.com/downloads
```

### 3. Important Permission Notes

Ubuntu authentication log collection may require sudo or root permissions because authentication logs contain sensitive information.

Windows Security log collection may require Administrator PowerShell because Windows Security logs contain sensitive information.

The collection scripts only read logs and export copies for analysis. They do not modify, delete, or disable system logs or security controls.

## Usage Guide

### Step 1: Run the Ubuntu Log Collector

On Ubuntu, go to the cloned project folder:

```bash
cd incident_log_project
```

Run the Ubuntu collector:

```bash
sudo python3 collect_ubuntu_auth.py
```

Enter the start and end time when asked.

Example time format:

```text
2026-05-20T00:00:00+05:30
2026-05-20T23:59:59+05:30
```

Expected output example:

```text
Ubuntu Auth Log Collector
Time format example: 2026-04-22T00:00:00+05:30

Enter start time: 2026-04-22T00:00:00+05:30
Enter end time: 2026-04-22T23:59:59+05:30

Reading these log files:
- /var/log/auth.log
- /var/log/auth.log.1
- /var/log/auth.log.2.gz
- /var/log/auth.log.3.gz
- /var/log/auth.log.4.gz

Collection complete.
Lines collected: 169
Output saved to: collected_logs/ubuntu_auth_collected.log
```

The Ubuntu collector is designed for Ubuntu and Debian-style authentication logs. It can be extended to other Linux distributions by changing the log file path and timestamp parser.

### Step 2: Run the Windows Security Log Collector

Open PowerShell as Administrator on Windows.

Go to the cloned project folder:

```powershell
cd incident_log_project
```

Run the Windows collector using a one-time execution policy bypass:

```powershell
powershell -ExecutionPolicy Bypass -File ./collect_windows_security.ps1
```

Enter the start and end time when asked.

Example time format:

```text
2026-05-20 00:00:00
2026-05-20 23:59:59
```

Expected output example:

```text
Windows Security Log Collector
Time format example: 2026-04-22 00:00:00

Enter start time: 2026-05-12 00:00:00
Enter end time: 2026-05-12 23:59:59

Collecting Event IDs: 4624, 4625
Start Time: 05/12/2026 00:00:00
End Time: 05/12/2026 23:59:59

Collection complete.
Events collected: 187
Output saved to: C:/incident_log_project/collected_logs/windows_security_events.csv
```

This execution policy bypass only applies to that command execution. It does not permanently change the system execution policy.

### Step 3: Move the Windows CSV to the Ubuntu Copy of the Project

The normalizer and analyzer are run from Ubuntu. After collecting Windows logs, copy this file from the Windows cloned project folder:

```text
collected_logs/windows_security_events.csv
```

To the Ubuntu cloned project folder:

```text
collected_logs/windows_security_events.csv
```

On Ubuntu, confirm both collected log files are present:

```bash
ls -lh collected_logs
```

Expected files:

```text
ubuntu_auth_collected.log
windows_security_events.csv
```

### Step 4: Run the Normalizer

On Ubuntu, from the cloned project folder, run:

```bash
python3 normalize_logs.py
```

Expected output example:

```text
Log Normalizer
Normalizing Linux and Windows logs.

Normalization complete.
Ubuntu rows: 78
Windows rows: 184
Total rows written: 262
Output saved to: normalized_logs.csv
```

The normalizer creates:

```text
normalized_logs.csv
```

Common normalized columns:

```text
timestamp, source_ip, host, event_type, user, raw_message
```

### Step 5: Run the Analyzer

On Ubuntu, run:

```bash
python3 analyze_logs.py
```

Expected output example:

```text
Security Incident Analyzer
Using expanded general framework-aligned rules.

Analysis complete.
Normalized rows read: 262
Incidents written: 6
Output saved to: incident_summary.csv
```

The analyzer creates:

```text
incident_summary.csv
```

## Viewing CSV Results

The main final output is:

```text
incident_summary.csv
```

You can open it using LibreOffice Calc on Ubuntu.

Install LibreOffice Calc if needed:

```bash
sudo apt install libreoffice-calc -y
```

Open the CSV:

```bash
libreoffice --calc incident_summary.csv
```

Recommended CSV import settings:

```text
Character set: Unicode (UTF-8)
Separator: comma
Text delimiter: double quote
```

You can use LibreOffice Calc to export a CSV as an HTML file for cleaner viewing in a web browser.

1.  **Open** `incident_summary.csv` in LibreOffice Calc.
2.  Go to **File > Save As**.
3.  Choose **HTML Document (.html)** as the file type.
4.  **Save** the file.
5.  **Open** the saved `.html` file in a browser for a cleaner table view.

Alternative terminal option:

```bash
sudo apt install csvkit -y
csvlook incident_summary.csv | less -S
```


## Detection Logic

The analyzer uses transparent rule-based detection.

Main detection rules include:

1. Single failed login
2. Repeated failed logins
3. High-volume failed logins
4. Windows network or SMB failed login detection
5. Successful login after repeated failures
6. Same source IP targeting multiple users
7. Same user targeted from multiple source IPs
8. Privilege activity after suspicious login
9. Many successful logins from the same source
10. Optional port scan row support
11. Multi-host suspicious activity correlation

## Severity Logic

| Severity | Meaning | Example |
|---|---|---|
| Low | Not urgent by itself | Single failed login |
| Medium | Suspicious and should be reviewed | Several failed logins |
| High | Serious and should be investigated soon | 5 or more failed logins |
| Critical | Should be checked first | Successful login after repeated failures or multi-host suspicious activity |

## Framework Mappings

The analyzer maps incidents to cybersecurity frameworks such as NIST CSF, NIST SP 800-61 and MITRE ATT&CK to make the results easier to explain professionally.

>**Important note:** The analyzer does not directly execute Sigma rules, Chainsaw, or Wazuh rules. It uses transparent Python rules inspired by common incident response logic and maps each detection to NIST CSF, NIST SP 800-61, and MITRE ATT&CK.

Sigma, Chainsaw, or Wazuh may be used separately later for optional validation or comparison.

## Ethical and Safety Note

This project should only be used in your own lab or on systems where you have permission.

The simulations used for this project were performed in a controlled VMware lab using owned virtual machines.

The collection scripts require administrator or root permissions because authentication and security logs contain sensitive information.

The scripts only read logs and export copies for analysis. They do not:

- modify logs
- delete logs
- disable logging
- weaken security settings
- block users
- change firewall rules automatically

## Final Note

This project demonstrates a simple security incident analysis process:

```text
collect -> normalize -> analyze -> prioritize -> explain
```

The final result helps answer the main investigation question:

**Which incident should be investigated first, and why?**
