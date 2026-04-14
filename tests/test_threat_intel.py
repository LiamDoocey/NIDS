import sys
import os

# Add the src directory to the system path to allow imports from there
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from src.threat_intel import ThreatIntel

threat_intel = ThreatIntel()

#Test with a known malicious IP
result = threat_intel.check_ip('222.89.169.98')
print(f"Checking known malicious IP: {result}")
#Test with a known clean IP
result = threat_intel.check_ip('8.8.8.8')
print(f"Checking known clean IP: {result}")
#Test with a private IP
result = threat_intel.check_ip('192.168.1.1')
print(f"Checking private IP: {result}")

print(f"Cache after tests: {threat_intel.cache}")
