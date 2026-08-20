# Python Security log Analyzer 

A Python-based cyvbersecurity tool that analyses authentication logs, identifies failed login acitivity, detects potential brute-force attacks, classifies security events by severity and generates a CSV security report.

## Overview

The Security Log Analyzer was developed as a practical cybersecurity project to demonstrate Python programming, log analysis, security-even detetction, error handling, automated testing and Git/Github workflow.

The tool processes authentication log entries and groups failed login attempts by IP address, it assigns a security severity leevel and identifies potentially suspicious activity.

## Features

- Authentication log parsing
- Failed login detection
- IP address extraction
- Username extraction
- Failed-attempt counting
- First and last attempt tracking
- Security severity classification
- Potential brute-force detection
- CSV security reporting 
- Malformed log-entry handling
- Missin-file error handling 
- Command-line log-file selection
- Automated unit testing

## Detection Logic

The analyzer currently uses the foloowing thresholds:

| failed Attempts | Severity | Classification |
|---|---|---|
| 1-2 | LOW | normal/low-risk activity |
| 3-4 | MEDIUM | Suspicious login activity |
| 5+ | HIGH | Possible brute-force attack |

A threshold of **5 failed login attempts** is currently used to flag potential brute-force activity.

## Technologies

- Python 3
- Python `argpasre`
- Python `csv`
- Python `pathlib`
- Python `unittest`
- Git
- GitHub

## Project Structure

```text
security-log-analyzer/
│
├── logs/
│   └── sample_auth.log
│
├── tests/
│   └── test_analyzer.py
│
├── analyzer.py
├── README.md
├── requirements.txt
├── .gitignore
└── LICENSE
```

## Installation

Clone the repository:
```bash
git clone https://github.com/stephenakpoiwa/security-log-analyzer.git
```
Navigate into the project:
```bash
cd security-log-analyzer
```
Create avirtual environbment:
```bash
python -m venv .venv
```
Activate the virtual environment on Windows Powershell:
```PowerShell
.venv\Scripts\Activate.ps1
```
No external Python packages are currently required because the analyzer uses Python standard-library modules.

## Usage

Run the analyzer by specifying the log file:
```PowerShell
python analyzer.py --log logs/samples=auth.log
```
To view the available command-line options:
```PowerShell
python analyzer.py --help
```

## Example Output

```
Security Log Analysis
======================

----------------------
Severity: MEDIUM
Status: Suspicious login activity
IP Address: 192.168.1.50
Username: admin
Failed Attempts: 4
First Attempt: 2026-08-08 08:22:11
Last Attempt: 2026-08-08 08:22:24

----------------------
Severity: LOW
Status: Normal/low-risk activity
IP Address: 192.168.1.60
Username: john
Failed Attempts: 2
First Attempt: 2026-08-08 09:45:12
Last Attempt: 2026-08-08 09:45:18

----------------------
Severity: HIGH
Status: Possible brute-force attack detected
IP Address: 192.168.1.75
Username: admin
Failed Attempts: 5
First Attempt: 2026-08-08 10:15:45
Last Attempt: 2026-08-08 10:16:12

```
The analyzer also generates:

```
security_report.csv
```
The CSV report contains:
- Severity
- Status
- IP Address
- Username
- Failed Attempts
- First Attempt
- Last Attempt

## Testing

The project includes an automated test suite using Python's built-in `unittest` framework.

Run all tests with:

```PowerShell
python -m unittest discover -s tests -v
```
Current test status:
```
12 tests passed
```
The tests cover:

- Severity classification
- Security status classification
- Failed-login counting
- Username extraction
- Timestamp tracking
- Malformed log entries
- Missing log files

## Security Considerations

This project is intended for educational and defensive cybersecurity purposes.

The analyzer should be used only with logs that you are authorized to access and analyze.

The current detection method is rule-based and should not be considered a complete intrusion-detection system.

## Futures Improvements

Potential future improvements include:

- Configurable brute-force thresholds
- Support for additional log formats
- JSON reporting
- Real-time log monitoring
- Dashboard visualization
- IP reputation checking
- More advanced anomaly detection
- Intergation with SIEM platforms 
- Email or webhook alerts

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.