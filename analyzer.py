from pathlib import Path
import csv
import argparse

BRUTE_FORCE_THRESHOLD = 5

def parse_log_file(log_file):
    """Read a log file and return failed-login information."""

    failed_logins = {}

    try:
        with log_file.open("r", encoding="utf-8") as file:

            for line in file:

                line = line.strip()

                if not line:
                    continue

                if "Failed login" not in line:
                    continue

                try:
                    parts = line.split(" - ")

                    if len(parts) != 3:
                        raise ValueError("Unexpected log format")

                    timestamp = parts[0].split(" WARNING")[0]
                    username = parts[1].replace("User: ", "").strip()
                    ip_address = parts[2].replace("IP: ", "").strip()

                    if not username:
                        raise ValueError("Missing Username")

                    if not ip_address:
                        raise ValueError("Missing IP address")

                    # Create a new entry only the first time we see the IP Address.
                    if ip_address not in failed_logins:

                        failed_logins[ip_address] = {"username": username, "attempts": 0, "first_attempt": timestamp, "last_attempt": timestamp}

                    # Increase the counter for every failed login from this IP.
                    failed_logins[ip_address]["attempts"] += 1

                    # Update the most recent attempt.
                    failed_logins[ip_address]["last_attempt"] = timestamp

                except (IndexError, ValueError) as error:

                    print(f"[WARNING] Malformed log entry skipped: {line}")
                    print(f"Reason: {error}")

                    continue
    except FileNotFoundError:
        raise FileNotFoundError(f"Log file not found: {log_file}")

    return failed_logins

def determine_severity(attempts):
    """Determine security severity based on failed attemopts."""

    if attempts >= BRUTE_FORCE_THRESHOLD:
        return "HIGH"

    elif attempts >= 3:
        return "MEDIUM"

    else: 
        return "LOW"

def determine_status(severity):
    """Return a description for the severity level."""

    if severity == "HIGH":
        return "Possible brute-force attack detected"

    elif severity == "MEDIUM":
        return "Suspicious login activity"

    else:
        return "Normal/low-risk activity"

def generate_report(failed_logins, report_file):
    """Generate a CSV security report."""

    with open(report_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        writer.writerow(["Severity", "Status", "IP Address", "Username", "Failed Attempts", "First Attempt", "Last Attempt"])

        for ip_address, details in failed_logins.items():
        
                attempts = details["attempts"]

                severity = determine_severity(attempts)

                status = determine_status(severity)
                
                writer.writerow([severity, status, ip_address, details["username"], attempts, details["first_attempt"], details["last_attempt"]])

def display_results(failed_logins):
    """Display security findings in the terminal."""

    print("\nSecurity Log Analysis")
    print("=" * 22)

    for ip_address, details in failed_logins.items():
        attempts = details["attempts"]

        severity = determine_severity(attempts)

        status = determine_status(severity)

        print("\n" + "-" * 22)

        print(f"Severity: {severity}")
        print(f"Status: {status}")
        print(f"IP Address: {ip_address}")
        print(f"Username: {details['username']}")
        print(f"Failed Attempts: {attempts}")
        print(f"First Attempt: {details['first_attempt']}")
        print(f"Last Attempt: {details['last_attempt']}")

def get_arguments():
    """Process command-line arguments."""

    pasrer = argparse.ArgumentParser(description=("Analyze authentication logs " "for suspicious activity."))

    pasrer.add_argument("--log", required=True, help="Path to the authentication log file")

    return pasrer.parse_args()

def main():
    """Run the security log analyzer."""

    args = get_arguments()

    log_file = Path(args.log)

    report_file =  "security_report.csv"

    try:
        failed_logins = parse_log_file(log_file)

        display_results(failed_logins)

        generate_report(failed_logins, report_file)

        print(f"\nSecurity report saved to: {report_file}")

    except FileNotFoundError as error:

        print(f"\nERROR: {error}")

        print("Please make sure the log file exists in the specified location.")


if __name__ == "__main__":
    main()