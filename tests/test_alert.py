import sys
import os

# Add the src directory to the system path to allow imports from there
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
from src.alerts import AlertManager

alert_manager = AlertManager()

alert_manager.subscribe(os.getenv('PERSONAL_PHONE_NUMBER'))

alert_manager.send_alert(
    label = 'TEST_ATTACK',
    confidence = 97.25,
    src_ip = '192.168.1.100',
    dst_ip = '192.168.1.1',
    src_port = 12345,
    dst_port = 80,
    protocol = 'TCP'
)