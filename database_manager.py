import sqlite3
import os
from datetime import datetime

DB_FILE = "data/ids_database.db"

def init_db():
    if not os.path.exists("data"):
        os.makedirs("data")
        
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Attacks Table
    c.execute('''CREATE TABLE IF NOT EXISTS attacks
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  src_ip TEXT,
                  dst_ip TEXT,
                  duration REAL,
                  count INTEGER,
                  protocol TEXT,
                  status TEXT)''')
                  
    # Blocked IPs Table
    c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips
                 (ip TEXT PRIMARY KEY,
                  timestamp TEXT,
                  reason TEXT)''')

    # Whitelist Table
    c.execute('''CREATE TABLE IF NOT EXISTS whitelist
                 (ip TEXT PRIMARY KEY,
                  timestamp TEXT,
                  description TEXT)''')
                  
    conn.commit()
    conn.close()

# ... (Logging functions remain same) ...

def add_whitelist(ip, description="User Added"):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("INSERT OR REPLACE INTO whitelist (ip, timestamp, description) VALUES (?, ?, ?)",
                  (ip, timestamp, description))
        conn.commit()
        conn.close()
        return True
    except:
        return False

def get_attack_stats_history(limit=10):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Group by last 10 minutes/intervals
    # SQLite doesn't have great date functions, string slicing works for simple YYYY-MM-DD HH:MM:SS
    # We will just get the last N entries and aggregate in python or get timestamp counts
    c.execute("SELECT timestamp FROM attacks ORDER BY id DESC LIMIT 100")
    rows = c.fetchall()
    conn.close()
    
    # Simple Python Aggregation
    timeline = {}
    for r in rows:
        # r[0] is time string. Assumed format %H:%M:%S or full date
        # If it's just HH:MM:SS, let's take the minute
        try:
            time_str = r[0]
            if len(time_str) > 8: # Full date
                 key = time_str[11:16] # HH:MM
            else:
                 key = time_str[:5] # HH:MM
            
            timeline[key] = timeline.get(key, 0) + 1
        except:
            pass
            
    # Fill gaps? No, just return list
    return [{"time": k, "count": v} for k, v in sorted(timeline.items())]

def get_whitelist():
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT ip FROM whitelist")
        rows = [row['ip'] for row in c.fetchall()]
        conn.close()
        return set(rows)
    except:
        return set()

def get_whitelist_details():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM whitelist ORDER BY timestamp DESC")
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows

def get_recent_attacks(limit=50):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM attacks ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows

def get_stats():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM attacks")
    total_attacks = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM blocked_ips")
    blocked_count = c.fetchone()[0]
    conn.close()
    return total_attacks, blocked_count

# Initial Setup
if __name__ == "__main__":
    init_db()
    print("Database Initialized")
