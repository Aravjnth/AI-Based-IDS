import sys
import os

# Add parent directory to path to find database_manager
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, render_template, jsonify
import database_manager as db

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/stats')
def stats():
    try:
        attacks = db.get_recent_attacks(50)
        total_attacks, blocked_count = db.get_stats()
        chart_data = db.get_attack_stats_history()
        
        # Format rows for JSON
        attack_list = []
        for row in attacks:
            attack_list.append({
                "timestamp": row["timestamp"],
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "protocol": row["protocol"],
                "status": row["status"]
            })
            
        return jsonify({
            "total_detections_all_time": total_attacks,
            "blocked_count": blocked_count,
            "recent_attacks": attack_list,
            "chart_data": chart_data
        })
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": str(e)})

from flask import request
@app.route('/api/whitelist', methods=['GET', 'POST'])
def whitelist_ip():
    if request.method == 'GET':
        return jsonify(db.get_whitelist_details())

    data = request.json
    ip = data.get('ip')
    if ip:
        db.add_whitelist(ip, "Dashboard Action")
        return jsonify({"success": True})
    return jsonify({"success": False})

@app.route('/api/report_attack', methods=['POST'])
def report_attack():
    data = request.json
    # Validation (Basic)
    if not data or 'src_ip' not in data:
        return jsonify({"status": "error", "message": "Invalid data"}), 400
    
    # Store in DB (Simulating Cloud DB Aggregation)
    db.log_attack(
        src_ip=data.get('src_ip'),
        dst_ip=data.get('dst_ip'),
        duration=data.get('duration', 0),
        count=data.get('count', 0),
        protocol=data.get('protocol', 'TCP')
    )
    print(f"☁️ Cloud Received Attack Report from {data.get('agent_id', 'Unknown')}")
    return jsonify({"status": "success"})

if __name__ == '__main__':
    print("🚀 Enterprise Dashboard running on http://127.0.0.1:5000")
    app.run(debug=True, port=5000)
