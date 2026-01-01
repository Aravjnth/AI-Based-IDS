
# 📦 CORTEX IDS - Deployment Manual

## Phase 1: Productization (Create executable)
Turn your Python script into a standalone Windows Application.

### Step 1: Install Builder
We use PyInstaller to compile the code.
`pip install pyinstaller`

### Step 2: Build the Agent (Sensor)
Run this command to create the background sensor service:
`pyinstaller --onefile --name Cortex_Sensor --hidden-import=sklearn --hidden-import=pandas --hidden-import=plyer --icon=NONE real_time_ids.py`

### Step 3: Build the Dashboard (Server)
Run this command to create the UI server:
`pyinstaller --onefile --name Cortex_Dashboard --add-data "dashboard/templates;dashboard/templates" --hidden-import=flask --icon=NONE dashboard/app.py`

---

## Phase 2: Active Defense (Enable Blocking)
Turn the system from "Passive Monitoring" to "Active Protection".

### Step 1: Edit Configuration
Open `config.json` and change:
`"enable_firewall_block": false` -> `"enable_firewall_block": true`

### Step 2: Run as Administrator
For the blocking to work, the **Cortex_Sensor.exe** must be run as Administrator (Right-click -> Run as Admin).

---

## Phase 3: Mobile Alerts (Discord/Telegram)
Get notified on your phone.

### Step 1: Get a Webhook URL
(e.g., in Discord Channel Settings -> Integrations -> Webhooks)

### Step 2: Update Code
Add this to `real_time_ids.py`:
```python
def send_discord_alert(msg):
    requests.post("YOUR_WEBHOOK_URL", json={"content": msg})
```

---

## Phase 4: Distribution
To give this to a client, zip these files:
1. `dist/Cortex_Sensor.exe`
2. `dist/Cortex_Dashboard.exe`
3. `config.json`
4. `model/` folder
5. `data/` folder (empty is fine)

**Instructions:**
1. Run `Cortex_Dashboard.exe`
2. Run `Cortex_Sensor.exe` (As Admin)
3. Open `http://localhost:5000`
