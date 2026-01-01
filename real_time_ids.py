import os
import sys
import time
import json
import logging
import joblib
import pandas as pd
import threading
import ipaddress
from datetime import datetime
from collections import deque
from scapy.all import sniff, IP, TCP, UDP
from plyer import notification
import requests
import database_manager as db

# ================= COLORS =================
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

# ================= CONFIGURATION =================
def load_config():
    with open("config.json", "r") as f:
        return json.load(f)

config = load_config()

MODEL_PATH = "model/ids_model.pkl"
ENABLE_FIREWALL_BLOCK = config.get("enable_firewall_black", False)
ENABLE_NOTIFICATIONS = config.get("enable_desktop_notifications", True)
WHITELIST_STRS = set(config.get("whitelist", []))

# ... imports
import dns.resolver, dns.reversename

# ... config loading ...

# Sync Whitelist from DB
DB_WHITELIST = set()
LAST_SYNC = 0

def sync_whitelist():
    global DB_WHITELIST, LAST_SYNC
    if time.time() - LAST_SYNC > 10: # Sync every 10s
        db_ips = db.get_whitelist()
        DB_WHITELIST = db_ips.union(WHITELIST_STRS)
        LAST_SYNC = time.time()

def is_whitelisted(ip):
    sync_whitelist()
    if ip in DB_WHITELIST:
        return True
    # Helper for Google/FB ranges
    if ip.startswith("142.250.") or ip.startswith("142.251."): return True
    return False

def get_hostname(ip):
    try:
        addr = dns.reversename.from_address(ip)
        return str(dns.resolver.resolve(addr, "PTR")[0])
    except:
        return "Unknown"

# ... FlowTracker ...

def show_notification(title, message):
    if not ENABLE_NOTIFICATIONS:
        return
    try:
        notification.notify(
            title=title,
            message=message,
            app_icon=None,
            timeout=5,
        )
    except:
        pass

# ================= LOAD MODEL =================
print(f"{CYAN}⏳ Loading AI Model...{RESET}")
if not os.path.exists(MODEL_PATH):
    print(f"{RED}❌ Model file not found at {MODEL_PATH}.{RESET}")
    sys.exit(1)

model = joblib.load(MODEL_PATH)
# Initialize DB
db.init_db()

print(f"{GREEN}✅ Model & Database Loaded!{RESET}")

# Features expected by the model
FEATURES = ["duration", "src_bytes", "dst_bytes", "count", "srv_count"]

# ================= FLOW TRACKER =================
class FlowTracker:
    def __init__(self):
        self.flows = {}
        self.history_window = 2.0
        self.connection_history = deque()

    def update_counts(self, current_time, src_ip, dst_ip, dst_port):
        while self.connection_history and current_time - self.connection_history[0][0] > self.history_window:
            self.connection_history.popleft()
        
        self.connection_history.append((current_time, src_ip, dst_ip, dst_port))
        
        count = 0
        srv_count = 0
        for t, s_ip, d_ip, d_port in self.connection_history:
            if d_ip == dst_ip:
                count += 1
            if d_port == dst_port:
                srv_count += 1      
        return count, srv_count

    def update_flow(self, packet):
        if not packet.haslayer(IP):
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if src_ip == "127.0.0.1" or dst_ip == "127.0.0.1":
            return None

        proto_num = packet[IP].proto
        protocol = "TCP" if proto_num == 6 else ("UDP" if proto_num == 17 else "OTHER")
        size = len(packet)
        current_time = time.time()
        
        src_port = 0
        dst_port = 0
        
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        flow_key = (src_ip, dst_ip, src_port, dst_port, proto_num)
        
        if flow_key not in self.flows:
            self.flows[flow_key] = {
                "start_time": current_time,
                "src_bytes": 0,
                "dst_bytes": 0,
                "last_seen": current_time
            }
        
        flow = self.flows[flow_key]
        flow["src_bytes"] += size
        flow["last_seen"] = current_time
        duration = current_time - flow["start_time"]
        
        count, srv_count = self.update_counts(current_time, src_ip, dst_ip, dst_port)

        return {
            "duration": duration,
            "src_bytes": flow["src_bytes"],
            "dst_bytes": 0,
            "count": count,
            "srv_count": srv_count,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol
        }

tracker = FlowTracker()
blocked_ips = set()

# ================= ACTIONS =================
def block_ip(ip):
    if ip in blocked_ips:
        return
    blocked_ips.add(ip)
    
    db.log_block(ip, "ML High Confidence Detection")
    print(f"{RED}🛑 BLOCKING MALICIOUS IP: {ip}{RESET}")
    
    show_notification("IDS Alert", f"Blocked Malicious IP: {ip}")

    if ENABLE_FIREWALL_BLOCK:
        try:
            cmd = f"netsh advfirewall firewall add rule name=\"AI_IDS_BLOCK_{ip}\" dir=in action=block remoteip={ip}"
            os.system(cmd)
            print(f"{RED}   (Firewall Rule Added){RESET}")
        except:
            pass

# ================= PERFORMANCE ENGINE =================
import queue
import threading

PACKET_QUEUE = queue.Queue()
STOP_EVENT = threading.Event()

def processing_worker():
    """Confers High-Performance Asynchronous Processing"""
    print(f"{GREEN}🚀 AI Engine Started (Background Thread){RESET}")
    
    while not STOP_EVENT.is_set():
        try:
            # Wait for packet data (blocking with timeout to allow shutdown check)
            packet_data = PACKET_QUEUE.get(timeout=1)
        except queue.Empty:
            continue
            
        try:
            # CHECK WHITELIST
            if is_whitelisted(packet_data["src_ip"]):
                PACKET_QUEUE.task_done()
                continue
                
            # PREPARE FEATURES
            df_input = pd.DataFrame([{
                "duration": packet_data["duration"],
                "src_bytes": packet_data["src_bytes"],
                "dst_bytes": packet_data["dst_bytes"],
                "count": packet_data["count"],
                "srv_count": packet_data["srv_count"]
            }])

            # AI PREDICTION
            prediction = model.predict(df_input)[0]

            if prediction == 1: # Attack
                # Smart Filter (CDN Check)
                hostname = get_hostname(packet_data["src_ip"])
                if any(x in hostname for x in ["google", "facebook", "microsoft", "1e100", "akamai", "cloudfront", "fastly"]):
                     db.add_whitelist(packet_data["src_ip"], f"Auto-Safe: {hostname}")
                     PACKET_QUEUE.task_done()
                     continue

                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"{RED}🚨 DETECTED: {packet_data['src_ip']} -> {packet_data['dst_ip']} | {hostname}{RESET}")
                
                # LOCAL LOG
                db.log_attack(packet_data["src_ip"], packet_data["dst_ip"], packet_data["duration"], packet_data["count"], packet_data["protocol"])
                
                # CLOUD REPORT (Non-blocking)
                try:
                    cloud_cfg = config.get("cloud_config", {})
                    url = f"{cloud_cfg.get('dashboard_url')}/api/report_attack"
                    payload = {
                        "agent_id": cloud_cfg.get("agent_id"),
                        "timestamp": timestamp,
                        "src_ip": packet_data["src_ip"],
                        "dst_ip": packet_data["dst_ip"],
                        "duration": packet_data["duration"],
                        "count": packet_data["count"],
                        "protocol": packet_data["protocol"]
                    }
                    threading.Thread(target=lambda: requests.post(url, json=payload, timeout=2)).start()
                except:
                    pass
                
                # BLOCKING ACTION
                if packet_data["src_ip"] not in blocked_ips:
                     block_ip(packet_data["src_ip"])

        except Exception as e:
            print(f"Error in worker: {e}")
        finally:
            PACKET_QUEUE.task_done()

def process_packet(packet):
    """Lightweight Sniffer - Pushes to Queue only"""
    try:
        data = tracker.update_flow(packet)
        if data:
            PACKET_QUEUE.put(data)
    except:
        pass

# ================= MAIN =================
def main():
    print(f"\n{CYAN}🛡️  ENTERPRISE IDS RUNNING (Use Ctrl+C to Stop){RESET}")
    print(f"   - Database: SQLite (data/ids_database.db)")
    print(f"   - Notifications: {'Enabled' if ENABLE_NOTIFICATIONS else 'Disabled'}")
    print(f"   - Firewall Block: {'Enabled' if ENABLE_FIREWALL_BLOCK else 'Disabled'}")
    print("-" * 50)

    try:
        # Start Worker Thread
        worker_t = threading.Thread(target=processing_worker, daemon=True)
        worker_t.start()
        
        sniff(prn=process_packet, store=0)
    except KeyboardInterrupt:
        STOP_EVENT.set()
        print(f"\n{YELLOW}⚠️  Ids Stopped.{RESET}")
    except Exception as e:
        print(f"\n{RED}❌ Error: {e}{RESET}")

if __name__ == "__main__":
    main()
