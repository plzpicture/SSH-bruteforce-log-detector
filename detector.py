import re
import csv
from collections import defaultdict, deque
from datetime import datetime

import matplotlib.pyplot as plt


LOG_FILE = "sample_logs/sample_auth.log"
CSV_OUTPUT_FILE = "outputs/suspicious_ips.csv"
REPORT_OUTPUT_FILE = "outputs/security_report.md"
GRAPH_OUTPUT_FILE = "outputs/failed_attempts_by_ip.png"

THRESHOLD = 3
WINDOW_MINUTES = 5


def parse_failed_login(line):
    if "Failed password" not in line:
        return None

    time_match = re.match(r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})", line)
    if not time_match:
        return None

    timestamp_text = time_match.group(1)
    timestamp = datetime.strptime(f"2026 {timestamp_text}", "%Y %b %d %H:%M:%S")

    ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
    if not ip_match:
        return None

    user_match = re.search(r"Failed password for (?:invalid user )?(\S+)", line)
    username = user_match.group(1) if user_match else "unknown"

    return {
        "timestamp": timestamp,
        "ip": ip_match.group(1),
        "username": username,
        "raw_log": line.strip()
    }


def load_failed_events(log_file):
    events = []

    with open(log_file, "r", encoding="utf-8-sig") as file:
        for line in file:
            event = parse_failed_login(line)
            if event:
                events.append(event)

    events.sort(key=lambda x: x["timestamp"])
    return events


def count_failed_attempts_by_ip(events):
    counts = defaultdict(int)

    for event in events:
        counts[event["ip"]] += 1

    return counts


def detect_with_sliding_window(events, threshold, window_minutes):
    events_by_ip = defaultdict(list)

    for event in events:
        events_by_ip[event["ip"]].append(event)

    suspicious_ips = []
    window_seconds = window_minutes * 60

    for ip, ip_events in events_by_ip.items():
        window = deque()
        max_attempts_in_window = 0
        targeted_users = set()
        first_detected_time = None
        last_detected_time = None

        for event in ip_events:
            current_time = event["timestamp"]
            window.append(event)
            targeted_users.add(event["username"])

            while (current_time - window[0]["timestamp"]).total_seconds() > window_seconds:
                window.popleft()

            if len(window) > max_attempts_in_window:
                max_attempts_in_window = len(window)

            if len(window) >= threshold:
                first_detected_time = window[0]["timestamp"]
                last_detected_time = window[-1]["timestamp"]
                break

        if max_attempts_in_window >= threshold:
            suspicious_ips.append({
                "ip": ip,
                "failed_attempts_in_window": max_attempts_in_window,
                "window_minutes": window_minutes,
                "targeted_users": ", ".join(sorted(targeted_users)),
                "first_detected_time": first_detected_time.strftime("%Y-%m-%d %H:%M:%S"),
                "last_detected_time": last_detected_time.strftime("%Y-%m-%d %H:%M:%S"),
                "risk_level": "High"
            })

    return suspicious_ips


def save_to_csv(suspicious_ips, output_file):
    with open(output_file, "w", newline="", encoding="utf-8-sig") as csvfile:
        fieldnames = [
            "ip",
            "failed_attempts_in_window",
            "window_minutes",
            "targeted_users",
            "first_detected_time",
            "last_detected_time",
            "risk_level"
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for item in suspicious_ips:
            writer.writerow(item)


def save_markdown_report(suspicious_ips, output_file, threshold, window_minutes):
    with open(output_file, "w", encoding="utf-8") as report:
        report.write("# SSH Brute Force Detection Report\n\n")

        report.write("## 1. Detection Rule\n\n")
        report.write(
            f"This report flags an IP address as suspicious when it generates "
            f"{threshold} or more failed SSH login attempts within {window_minutes} minutes.\n\n"
        )

        report.write("## 2. Summary\n\n")
        report.write(f"- Suspicious IPs detected: {len(suspicious_ips)}\n")
        report.write(f"- Threshold: {threshold} failed attempts\n")
        report.write(f"- Time window: {window_minutes} minutes\n\n")

        report.write("## 3. Suspicious IPs\n\n")

        if not suspicious_ips:
            report.write("No suspicious IPs were detected.\n\n")
        else:
            report.write("| IP Address | Failed Attempts | Window | Targeted Users | Time Range | Risk |\n")
            report.write("|---|---:|---:|---|---|---|\n")

            for item in suspicious_ips:
                time_range = f"{item['first_detected_time']} ~ {item['last_detected_time']}"
                report.write(
                    f"| {item['ip']} "
                    f"| {item['failed_attempts_in_window']} "
                    f"| {item['window_minutes']} min "
                    f"| {item['targeted_users']} "
                    f"| {time_range} "
                    f"| {item['risk_level']} |\n"
                )

            report.write("\n")

        report.write("## 4. Security Interpretation\n\n")
        report.write(
            "The detected IP addresses generated repeated failed SSH login attempts "
            "within a short time window. This behavior may indicate SSH brute-force "
            "activity or automated password guessing attempts.\n\n"
        )

        report.write("## 5. Limitations\n\n")
        report.write("- This tool analyzes stored log files, not real-time traffic.\n")
        report.write("- The current detection logic is threshold-based.\n")
        report.write("- Slow brute-force attacks may avoid detection.\n")
        report.write("- Different Linux distributions may use slightly different SSH log formats.\n\n")

        report.write("## 6. Ethical Use\n\n")
        report.write(
            "This project is intended for defensive security education and authorized log analysis only. "
            "It should not be used for unauthorized access attempts, scanning, or attacking real systems.\n"
        )


def save_failed_attempts_graph(failed_attempts_by_ip, output_file):
    if not failed_attempts_by_ip:
        return

    ips = list(failed_attempts_by_ip.keys())
    counts = list(failed_attempts_by_ip.values())

    plt.figure(figsize=(10, 6))
    plt.bar(ips, counts)
    plt.title("Failed SSH Login Attempts by IP")
    plt.xlabel("IP Address")
    plt.ylabel("Failed Attempts")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()


def main():
    events = load_failed_events(LOG_FILE)

    failed_attempts_by_ip = count_failed_attempts_by_ip(events)

    suspicious_ips = detect_with_sliding_window(
        events,
        THRESHOLD,
        WINDOW_MINUTES
    )

    print("=== SSH Brute Force Sliding Window Detection Result ===")
    print(f"Rule: {THRESHOLD}+ failed login attempts within {WINDOW_MINUTES} minutes\n")

    if not suspicious_ips:
        print("No suspicious IPs detected.")
    else:
        for item in suspicious_ips:
            print(
                f"[{item['risk_level']}] IP: {item['ip']} | "
                f"Failed Attempts: {item['failed_attempts_in_window']} within "
                f"{item['window_minutes']} minutes | "
                f"Targeted Users: {item['targeted_users']} | "
                f"Time Range: {item['first_detected_time']} ~ {item['last_detected_time']}"
            )

    save_to_csv(suspicious_ips, CSV_OUTPUT_FILE)
    save_markdown_report(
        suspicious_ips,
        REPORT_OUTPUT_FILE,
        THRESHOLD,
        WINDOW_MINUTES
    )
    save_failed_attempts_graph(failed_attempts_by_ip, GRAPH_OUTPUT_FILE)

    print(f"\nCSV result saved to {CSV_OUTPUT_FILE}")
    print(f"Markdown report saved to {REPORT_OUTPUT_FILE}")
    print(f"Graph saved to {GRAPH_OUTPUT_FILE}")


if __name__ == "__main__":
    main()
