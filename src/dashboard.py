from flask import Flask, render_template, jsonify, request
from alerts import AlertManager
from dotenv import load_dotenv
from datetime import datetime, timedelta
from database import *
import logging

load_dotenv()

app = Flask(
    __name__,
    template_folder = '../templates',
    static_folder = '../static'
)

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def get_stats_route():
    stats = get_stats()

    if 'start_time' not in app.config:
        app.config['start_time'] = datetime.now()

    uptime_seconds = (datetime.now() - app.config['start_time']).total_seconds()
    
    hours = int(uptime_seconds // 3600)
    minutes = int((uptime_seconds % 3600) // 60)
    seconds = int(uptime_seconds % 60)
    stats['uptime'] = f"{hours}h {minutes}m {seconds}s"

    return jsonify(stats)

@app.route('/api/traffic_history')
def get_traffic_history_route():
    interval = request.args.get('interval', 'hour')
    now = datetime.now()

    intervals = {
        'hour': timedelta(hours = 1),
        'day': timedelta(days = 1),
        'week': timedelta(weeks = 1),
        'month': timedelta(days = 30)
    }

    cutoff = now - intervals.get(interval, timedelta(hours = 1))

    return jsonify(get_traffic_history(cutoff))

@app.route('/api/alerts')
def get_alerts_route():
    return jsonify(get_alert_history())

def add_traffic_event(event_type, label, src_ip, dst_ip, src_port, dst_port, protocol, confidence):

    log_traffic_event(event_type)

    if event_type in ('ALERT', 'THREAT_INTEL_MATCH'):
        log_alert(event_type, label, src_ip, dst_ip, src_port, dst_port, protocol, confidence)


def start_dashboard(host = '0.0.0.0', port = 5000, debug = False):
    print(f"Starting dashboard on {host}:{port}...")
    app.run(host = host, port = port, debug = debug, threaded = True)

if __name__ == "__main__":
    start_dashboard()