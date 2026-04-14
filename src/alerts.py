import boto3
import json
import os
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class AlertManager:

    """Manages AWS SNS subscriptions and sends alerts when malicious flows are detected by the NIDS.
    Subscriptions are stored in a local JSON file to persist across sessions."""

    def __init__(self, region = 'eu-west-1'):

        """Initializes the AlertManager by setting up the SNS client and loading existing subscriptions from disk."""

        self.sns = boto3.client(
            'sns',
            region_name = region,
            aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key = os.getenv('AWS_SECRET_KEY')
        )

        #SNS topic ARN should be set in environment variables for the AlertManager to function properly.
        self.topic_arn = os.getenv('SNS_TOPIC_ARN')

        if not self.topic_arn:
            raise ValueError("SNS_TOPIC_ARN environment variable not set.")
        
        #Load existing subscriptions from disk or initialize an empty dictionary if the file doesn't exist.
        self.subcriptions = self._load_subscriptions()

    def _load_subscriptions(self):

        """Loads existing subscriptions from a local JSON file. If the file doesn't exist, returns an empty dictionary."""

        if os.path.exists('subscriptions.json'):
            with open('subscriptions.json', 'r') as f:
                return json.load(f)
        return {}
    
    def _save_subscriptions(self):

        """Saves the current subscriptions to a local JSON file to persist them across sessions."""

        with open('subscriptions.json', 'w') as f:
            json.dump(self.subcriptions, f)

    def subscribe(self, phone_number):

        """Subscribes a phone number to the SNS topic to receive SMS alerts. Returns True if successful, False otherwise."""

        try:
            if phone_number in self.subcriptions:
                print(f"{phone_number} is already subscribed.")
                return False
            
            response = self.sns.subscribe(
                TopicArn = self.topic_arn,
                Protocol = 'sms',
                Endpoint = phone_number
            )

            self.subcriptions[phone_number] = response['SubscriptionArn']
            self._save_subscriptions()
            print(f"Subscribed {phone_number} successfully.")
            return True
        
        except Exception as e:
            print(f"Error occurred while subscribing {phone_number}: {e}")
            return False
    
    def unsubscribe(self, phone_number):

        """Unsubscribes a phone number from the SNS topic. Returns True if successful, False otherwise."""

        try:
            if phone_number not in self.subcriptions:
                print(f"{phone_number} is not subscribed.")
                return False
            
            self.sns.unsubscribe(
                SubscriptionArn = self.subcriptions[phone_number]
            )

            del self.subcriptions[phone_number]
            self._save_subscriptions()

            print(f"Unsubscribed {phone_number} successfully.")
            return True
        
        except Exception as e:
            print(f"Error occurred while unsubscribing {phone_number}: {e}")
            return False
        
    def get_subscriptions(self):

        """Returns a list of currently subscribed phone numbers."""

        return list(self.subcriptions.keys())
    
    def send_alert(self, label, confidence, src_ip, dst_ip, src_port, dst_port, protocol):

        """Sends an alert via SNS with the details of the detected attack. Returns True if successful, False otherwise."""

        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            message = (
                f"NIDS ALERT\n"
                f"Time: {timestamp}\n"
                f"Attack Type: {label}\n"
                f"Confidence: {confidence:.2f}%\n"
                f"Flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n"
                f"Protocol: {protocol}"                                          
            )

            self.sns.publish(
                TopicArn = self.topic_arn,
                Message = message,
                Subject = f"NIDS Alert: {label} detected"
            )

            print(f"Alert sent successfully for {label} with {confidence:.2f}% confidence.")
            return True
        
        except Exception as e:
            print(f"Error occurred while sending alert: {e}")
            return False