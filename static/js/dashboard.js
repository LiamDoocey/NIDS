let trafficChart = null;
let activeInterval = 'hour';

function setChartInterval(interval){
    activeInterval = interval;

    document.querySelectorAll('.interval-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.textContent.toLowerCase() == interval) {
            btn.classList.add('active');
        }
    });
    updateChart();
}

function initChart(){
    const ctx = document.getElementById('traffic-chart').getContext('2d');

    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Benign',
                    data: [],
                    borderColor: '#3fb950',
                    backgroundColor: 'rgba(63, 185, 80, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Alerts',
                    data: [],
                    borderColor: '#f85149',
                    backgroundColor: 'rgba(248, 81, 73, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Threat Intel',
                    data: [],
                    borderColor: '#d29922',
                    backgroundColor: 'rgba(210, 153, 34, 0.1)',
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { labels: { color: '#8b949e' } }
            },
            scales: {
                x: {
                    ticks: { color: '#8b949e' },
                    grid: { color: '#21262d' }
                },
                y: {
                    ticks: { color: '#8b949e' },
                    grid: { color: '#21262d' },
                    beginAtZero: true
                }
            }
        }
    });
}

function updateChart(){
    fetch(`/api/traffic_history?interval=${activeInterval}`)
        .then(res => res.json())
        .then(data => {
            if (!trafficChart) return;

            trafficChart.data.labels = data.map(d => d.time);
            trafficChart.data.datasets[0].data = data.map(d => d.benign)
            trafficChart.data.datasets[1].data = data.map(d => d.alerts)
            trafficChart.data.datasets[2].data = data.map(d => d.threats)
            trafficChart.update();
        })
        .catch(err => console.error('Error fetching traffic history: ', err));
}

function updateStats(){
    fetch('/api/stats')
        .then(res => res.json())
        .then(data => {
            document.getElementById('total-flows').textContent = data.total_flows;
            document.getElementById('benign-flows').textContent = data.benign_flows;
            document.getElementById('alert-count').textContent = data.total_alerts;
            document.getElementById('threat-count').textContent = data.threat_intel_matches;
        })
        .catch(err => console.error('Error fetching stats: ', err));
}

function updateAlerts() {
    fetch('/api/alerts')
        .then(res => res.json())
        .then(data => {
            const list = document.getElementById('alert-list');

            if (data.length === 0) {
                list.innerHTML = '<p class="no-alerts">No alerts detected yet</p>';
                return;
            }

            list.innerHTML = data.map(alert => `
                <div class="alert-item ${alert.event_type}" onclick="showAlert(${JSON.stringify(alert).replace(/"/g, '&quot;')})">
                    <span class="alert-badge ${alert.event_type}">
                        ${alert.event_type === 'ALERT' ? 'ML ALERT' : 'THREAT INTEL'}
                    </span>
                    <span class="alert-summary">
                        <span>${alert.label}</span> —
                        ${alert.src_ip}:${alert.src_port} → ${alert.dst_ip}:${alert.dst_port}
                    </span>
                    <span class="alert-time">${alert.timestamp}</span>
                </div>
            `).join('');
        })
        .catch(err => console.error('Error fetching alerts:', err));
}

function showAlert(alert) {
    document.getElementById('modal-title').textContent = 
        alert.event_type === 'ALERT' ? 'ML Detection Alert' : 'Threat Intelligence Match';

    document.getElementById('modal-body').innerHTML = `
        <div class="modal-body-row">
            <span class="key">Time</span>
            <span class="value">${alert.timestamp}</span>
        </div>
        <div class="modal-body-row">
            <span class="key">Type</span>
            <span class="value">${alert.event_type === 'ALERT' ? 'ML Alert' : 'Threat Intel Match'}</span>
        </div>
        <div class="modal-body-row">
            <span class="key">Label</span>
            <span class="value">${alert.label}</span>
        </div>
        <div class="modal-body-row">
            <span class="key">Source</span>
            <span class="value">${alert.src_ip}:${alert.src_port}</span>
        </div>
        <div class="modal-body-row">
            <span class="key">Destination</span>
            <span class="value">${alert.dst_ip}:${alert.dst_port}</span>
        </div>
        <div class="modal-body-row">
            <span class="key">Protocol</span>
            <span class="value">${alert.protocol}</span>
        </div>
        <div class="modal-body-row">
            <span class="key">Confidence</span>
            <span class="value">${alert.confidence ? alert.confidence + '%' : 'N/A'}</span>
        </div>
    `;

    document.getElementById('alert-modal').classList.remove('hidden');
    document.getElementById('modal-overlay').classList.remove('hidden');
}

function closeModal() {
    document.getElementById('alert-modal').classList.add('hidden');
    document.getElementById('modal-overlay').classList.add('hidden');
}

initChart();
updateStats();
updateChart();

setInterval(() => {
    updateStats();
    updateChart();
    updateAlerts();
}, 5000); //Every 5 Seconds

updateAlerts(); //Onload