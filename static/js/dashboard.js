function updateStats() {
    try{
        fetch('/api/stats')
            .then(response => response.json())
            .then(data => {
                document.getElementById('total-flows').textContent = data.total_flows;
                document.getElementById('benign-flows').textContent = data.benign_flows;
                document.getElementById('alert-count').textContent = data.total_alerts;
                document.getElementById('threat-count').textContent = data.threat_intel_matches;
            });
    } catch (error) {
        console.error('Error fetching stats:', error);
    }
}

updateStats();
setInterval(updateStats, 5000); // Update every 5 seconds