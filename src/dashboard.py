from flask import Flask, render_template, jsonify
from alerts import AlertManager
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

app = Flask(
    __name__,
    template_folder = '../templates',
    static_folder = '../static'
)

alert_manager = AlertManager()

#Shared data store
dashboard_data = {
    'stats': {
        'total_flows': 0,
        'total_alerts': 0,
        'benign_flows': 0,
        'threat_intel_matches': 0,
        'start_time': datetime.now().isoformat()
    }
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    stats = dashboard_data['stats'].copy()

    start = datetime.fromisoformat(stats['start_time'])
    uptime_seconds = (datetime.now() - start).total_seconds()
    hours = int(uptime_seconds // 3600)
    minutes = int((uptime_seconds % 3600) // 60)
    seconds = int(uptime_seconds % 60)
    stats['uptime'] = f"{hours}h {minutes}m {seconds}s"

    return jsonify(stats)

def add_traffic_event(event_type, label, src_ip, dst_ip, src_port, dst_port, protocol, confidence = None):

    dashboard_data['stats']['total_flows'] += 1

    if event_type == 'ALERT':
        dashboard_data['stats']['total_alerts'] += 1
    elif event_type == 'THREAT_INTEL_MATCH':
        dashboard_data['stats']['threat_intel_matches'] += 1
    else:
        dashboard_data['stats']['benign_flows'] += 1

def start_dashboard(host = '0.0.0.0', port = 5000, debug = False):

    print(f"Starting dashboard on {host}:{port}...")
    app.run(host = host, port = port, debug = debug, threaded = True)

if __name__ == "__main__":
    start_dashboard()