import re
import csv
from collections import defaultdict


FAILED_LOGIN_THRESHOLD = 5
LOG_FILE = "sample.log"
OUTPUT_CSV = "log_analysis_results.csv"

#function to parse the log file content to list of strings
def parse_log_file(file_path):
    with open(file_path, 'r') as f:
        logs = f.readlines()
    return logs


#function to count the no of request pre IP address
def count_requests_per_ip(logs):
    ip_count = defaultdict(int)
    for log in logs:
        match = re.match(r"(\d+\.\d+\.\d+\.\d+)", log)
        if match:
            ip_count[match.group(1)] += 1
    sorted_ip_count = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)
    return sorted_ip_count

#function to identify the most frequently accessed endpoint
def most_frequently_accessed_endpoint(logs):
    endpoint_count = defaultdict(int)
    for log in logs:
        match = re.search(r'"[A-Z]+ (/\S*)', log)
        if match:
            endpoint_count[match.group(1)] += 1
    most_accessed = max(endpoint_count.items(), key=lambda x: x[1])
    return most_accessed

#function to identify IP with suspicious activity
def detect_suspicious_activity(logs, threshold):
    failed_attempts = defaultdict(int)
    for log in logs:
        if "401" in log or "Invalid credentials" in log:
            match = re.match(r"(\d+\.\d+\.\d+\.\d+)", log)
            if match:
                failed_attempts[match.group(1)] += 1
    flagged_ips = {ip: count for ip, count in failed_attempts.items() if count > threshold}
    return flagged_ips


def save_results_to_csv(ip_counts, most_accessed, suspicious_activity, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP to csv file
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_counts)
        writer.writerow([])

        # Write Most Accessed Endpoint to csv file
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])
        writer.writerow([])

        # Write Suspicious Activity to csv file
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_activity.items())

def main():
    logs = parse_log_file(LOG_FILE)

    ip_counts = count_requests_per_ip(logs)
    print("Requests per IP:")
    for ip, count in ip_counts:
        print(f"{ip:<20} {count}")

    most_accessed = most_frequently_accessed_endpoint(logs)
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    suspicious_activity = detect_suspicious_activity(logs, FAILED_LOGIN_THRESHOLD)
    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_activity.items():
        print(f"{ip:<20} {count}")

    save_results_to_csv(ip_counts, most_accessed, suspicious_activity, OUTPUT_CSV)
    print(f"\nResults saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
