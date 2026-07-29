import requests

class LLMClient:

    def generate_rca(self, incident):

        prompt = f"""
Analyze this Kubernetes incident.

Alert:
{incident.get('alert')}

Logs:
{incident.get('logs')}

Events:
{incident.get('events')}

Metrics:
{incident.get('metrics')}

Provide:
1. Root Cause
2. Confidence
3. Recommended Fix
"""

        return {
            "prompt": prompt
        }