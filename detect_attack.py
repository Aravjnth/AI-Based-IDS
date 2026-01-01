import pandas as pd
import joblib
import random
import time
from datetime import datetime

# ================= LOAD ML MODEL =================
model = joblib.load("model/ids_model.pkl")

# ================= LOAD DATA =================
df = pd.read_csv("data/sample_data.csv")

# ================= FEATURES =================
features = ["duration", "src_bytes", "dst_bytes", "count", "srv_count"]

# ================= IPS STORAGE =================
blocked_ips_file = "data/blocked_ips.txt"
incident_report_file = "data/detected_attacks.csv"
blocked_ips = set()
attack_logs = []

# ================= TERMINAL COLORS =================
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

# ================= UTILITY FUNCTIONS =================
def random_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

def block_ip(ip):
    if ip not in blocked_ips:
        blocked_ips.add(ip)
        with open(blocked_ips_file, "a") as f:
            f.write(ip + "\n")
        print(f"{GREEN}🛑 IPS ACTION: BLOCKED SOURCE IP → {ip}{RESET}")

# ================= START STREAM =================
print(f"\n{CYAN}🛡️ REAL-TIME IDS + IPS STREAMING STARTED{RESET}\n")

try:
    for index, row in df.iterrows():

        # Simulate real-time packet arrival
        time.sleep(0.3)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip = random_ip()
        dst_ip = random_ip()

        # Create a DataFrame with a single row to keep feature names
        X = pd.DataFrame([row[features]])
        prediction = model.predict(X)[0]

        if prediction == 1:
            print(
                f"{RED}➡️ ATTACK DETECTED | Time: {timestamp} | "
                f"Src IP: {src_ip} → Dst IP: {dst_ip} | Row: {index + 1}{RESET}"
            )

            block_ip(src_ip)

            attack_logs.append({
                "row": index + 1,
                "timestamp": timestamp,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "duration": row["duration"],
                "src_bytes": row["src_bytes"],
                "dst_bytes": row["dst_bytes"],
                "count": row["count"],
                "srv_count": row["srv_count"]
            })

        else:
            print(
                f"{YELLOW}🟢 NORMAL TRAFFIC | Time: {timestamp} | "
                f"Src IP: {src_ip} → Dst IP: {dst_ip}{RESET}"
            )
except KeyboardInterrupt:
    print(f"\n{YELLOW}⚠️  Monitoring Interrupted by User{RESET}")

# ================= SAVE REPORTS =================
if attack_logs:
    pd.DataFrame(attack_logs).to_csv(incident_report_file, index=False)

print(f"\n{CYAN}📊 STREAM SUMMARY{RESET}")
print(f"Total Records Processed : {len(df)}")
print(f"Total Attacks Detected  : {len(attack_logs)}")
print(f"Blocked IPs Stored In  : {blocked_ips_file}")
print(f"Incident Report Saved : {incident_report_file}")

print(f"\n{GREEN}🔐 IDS + IPS REAL-TIME MONITORING COMPLETED{RESET}")
