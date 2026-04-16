from flask import Flask, render_template, jsonify, request
from alerts import AlertManager
from dotenv import load_dotenv
from datetime import datetime, timedelta

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
    },
    'traffic_history': [],
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

@app.route('/api/traffic_history')
def get_traffic_history():
    interval = request.args.get('interval', 'hour')
    now = datetime.now()

    intervals = {
        'hour': timedelta(hours = 1),
        'day': timedelta(days = 1),
        'week': timedelta(weeks = 1),
        'month': timedelta(days = 30)
    }

    cutoff = now - intervals.get(interval, timedelta(hours = 1))

    filtered = [
        entry for entry in dashboard_data['traffic_history'] if datetime.fromisoformat(entry['timestamp']) >= cutoff
    ]

    return jsonify(filtered)

def add_traffic_event(event_type):

    dashboard_data['stats']['total_flows'] += 1

    if event_type == 'ALERT':
        dashboard_data['stats']['total_alerts'] += 1
    elif event_type == 'THREAT_INTEL_MATCH':
        dashboard_data['stats']['threat_intel_matches'] += 1
    else:
        dashboard_data['stats']['benign_flows'] += 1

    now = datetime.now().strftime('%H:%M')
    history = dashboard_data['traffic_history']

    if history and history[-1]['time'] == now:
        history[-1]['total'] += 1

        if event_type == 'ALERT':
            history[-1]['alerts'] += 1
        elif event_type == 'THREAT_INTEL_MATCH':
            history[-1]['threats'] += 1
        else:
            history[-1]['benign'] += 1
    else:
        history.append({
            'time': now,
            'timestamp': datetime.now().isoformat(),
            'total': 1, 
            'alerts': 1 if event_type == 'ALERT' else 0,
            'threats': 1 if event_type == 'THREAT_INTEL_MATCH' else 0,
            'benign': 1 if event_type == 'OK' else 0
        })
        dashboard_data['traffic_history'] = history[-30:]

def start_dashboard(host = '0.0.0.0', port = 5000, debug = False):
    print(f"Starting dashboard on {host}:{port}...")
    app.run(host = host, port = port, debug = debug, threaded = True)

if __name__ == "__main__":
    start_dashboard()