import re
from datetime import datetime
from collections import defaultdict

# === 1. Load log file ===
file_path = "web_activity.log"  # Make sure your log is in the same folder
with open(file_path, "r", encoding="utf-8") as f:
    log_data = f.read()

# === 2. Split by IP blocks ===
blocks = re.split(r"\n\s*\n", log_data.strip())

# Data structures
user_api_times = defaultdict(list)
ip_addresses = set()

# === 3. Extract IPs and timestamps ===
for block in blocks:
    lines = block.split("\n")
    if not lines:
        continue
    
    # The first line should be the IP address
    ip_line = lines[0].strip()
    ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", ip_line)
    if ip_match:
        ip = ip_match.group(1)
        ip_addresses.add(ip)
    else:
        ip = "UNKNOWN"
    
    # Extract API call timestamps and user IDs
    for line in lines:
        if "/api/factory/machine/status" in line:
            time_match = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)", line)
            user_match = re.search(r'authorizedUserId: "([^"]+)"', line)
            if time_match and user_match:
                time = datetime.strptime(time_match.group(1), "%Y-%m-%dT%H:%M:%S.%fZ")
                user = user_match.group(1)
                user_api_times[user].append(time)

# === 4. Detect suspicious timestamp intervals ===
suspicious_users = {}

for user, times in user_api_times.items():
    times.sort()
    if len(times) < 3:
        continue
    diffs = [(times[i+1] - times[i]).total_seconds() for i in range(len(times)-1)]
    
    # Check if all intervals are almost identical (±1 sec)
    if all(abs(d - diffs[0]) <= 1 for d in diffs):
        suspicious_users[user] = diffs

# === 5. Identify unrecognized IPs (non-internal) ===
def is_internal_ip(ip):
    return (
        ip.startswith("192.168.") or
        ip.startswith("10.") or
        ip.startswith("172.16.") or ip.startswith("172.17.") or ip.startswith("172.18.") or ip.startswith("172.19.") or
        ip.startswith("172.20.") or ip.startswith("172.21.") or ip.startswith("172.22.") or ip.startswith("172.23.") or
        ip.startswith("172.24.") or ip.startswith("172.25.") or ip.startswith("172.26.") or ip.startswith("172.27.") or
        ip.startswith("172.28.") or ip.startswith("172.29.") or ip.startswith("172.30.") or ip.startswith("172.31.")
    )

external_ips = [ip for ip in ip_addresses if not is_internal_ip(ip)]

# === 6. Print Results ===

print("🔍 Suspicious Automated Users (based on consistent timestamps):")
if suspicious_users:
    for user, diffs in suspicious_users.items():
        print(f"  ⚠️ {user} — intervals (sec): {diffs}")
else:
    print("  ✅ No users with automated (fixed interval) request patterns found.\n")

print("\n🌐 Unrecognized / External IP Addresses:")
if external_ips:
    for ip in external_ips:
        print(f"  ⚠️ {ip} — possible external access (not intranet)")
else:
    print("  ✅ No external IPs detected. All traffic is internal.\n")

# === 7. Activity Summary ===
user_api_counts = {user: len(times) for user, times in user_api_times.items()}
sorted_users = sorted(user_api_counts.items(), key=lambda x: x[1], reverse=True)

print("\n📊 Top 10 Most Active Users:")
for user, count in sorted_users[:10]:
    print(f"  {user:30} → {count} API calls")
