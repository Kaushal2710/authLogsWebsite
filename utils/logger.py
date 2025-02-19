import json
import time
import os
from datetime import datetime
from flask import request

class AuthLogger:
    def __init__(self, log_file):
        self.log_file = log_file
        # Create empty JSON file if it doesn't exist
        if not os.path.exists(log_file):
            with open(log_file, 'w') as f:
                json.dump([], f)
    
    def get_client_info(self):
        return {
            'ip_address': request.remote_addr,
            'user_agent': request.user_agent.string,
            'headers': dict(request.headers),
            'timestamp': datetime.now().isoformat()
        }
    
    def log_auth_event(self, event_type, username, success, details=None):
        client_info = self.get_client_info()
        
        log_entry = {
            'event_type': event_type,
            'username': username,
            'success': success,
            'timestamp': datetime.now().isoformat(),
            'client_info': client_info,
        }
        
        if details:
            log_entry['details'] = details
            
        # Read existing logs
        try:
            with open(self.log_file, 'r') as f:
                logs = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            logs = []
            
        # Append new log
        logs.append(log_entry)
        
        # Write updated logs
        with open(self.log_file, 'w') as f:
            json.dump(logs, f, indent=2)
            
        return log_entry