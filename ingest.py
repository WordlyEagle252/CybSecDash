import os
import requests
import json
from datetime import datetime

VT_KEY = os.environ.get("VT_API_KEY")
OTX_KEY = os.environ.get("OTX_API_KEY")

unified_data = []

def fetch_alienvault():
    if not OTX_KEY:
        print("OTX_KEY missing. Skipping AlienVault.")
        return
        
    print("Fetching AlienVault OTX...")
    headers = {"X-OTX-API-KEY": OTX_KEY}
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=10"
    
    try:
        response = requests.get(url, headers=headers)
        if response.ok:
            for pulse in response.json().get("results", []):
                unified_data.append({
                    "id": f"OTX-{pulse.get('id', '')[:8]}",
                    "severity": "HIGH",
                    "date": pulse.get("modified", "").split("T")[0],
                    "product": "Enterprise Infrastructure",
                    "source": "AlienVault OTX",
                    "desc": pulse.get("name", "Malicious infrastructure campaign detected."),
                    "remediation": "Deploy Indicators of Compromise (IOCs) to firewall perimeter. Block malicious outbound traffic."
                })
    except Exception as e:
        print(f"OTX Error: {e}")

def fetch_virustotal():
    if not VT_KEY:
        print("VT_KEY missing. Skipping VirusTotal.")
        return
        
    print("Fetching VirusTotal...")
    headers = {"accept": "application/json", "x-apikey": VT_KEY}
    url = "https://www.virustotal.com/api/v3/comments?limit=10"
    
    try:
        response = requests.get(url, headers=headers)
        if response.ok:
            for comment in response.json().get("data", []):
                attrs = comment.get("attributes", {})
                html_text = attrs.get("text", "")
                clean_text = (html_text[:120] + '...') if len(html_text) > 120 else html_text
                
                unified_data.append({
                    "id": f"VT-{comment.get('id', '')[:8]}",
                    "severity": "CRITICAL",
                    "date": datetime.today().strftime('%Y-%m-%d'),
                    "product": "Endpoint / System Artifact",
                    "source": "VirusTotal",
                    "desc": clean_text if clean_text else "Malicious file hash submitted for sandboxing.",
                    "remediation": "Isolate the host immediately. Run a comprehensive EDR artifact sweep for the associated hash identifier."
                })
    except Exception as e:
        print(f"VT Error: {e}")

def fetch_threatfox():
    print("Fetching ThreatFox Malware IOCs...")
    url = "https://threatfox-api.abuse.ch/api/v1/"
    payload = {"query": "get_iocs", "days": 1}
    
    try:
        response = requests.post(url, json=payload)
        if response.ok:
            data = response.json().get("data", [])
            for ioc in data[:15]: # Grab the latest 15 malware IOCs
                unified_data.append({
                    "id": f"TF-{ioc.get('ioc_id')}",
                    "severity": "CRITICAL",
                    "date": ioc.get("first_seen", "").split(" ")[0],
                    "product": ioc.get("threat_type", "Malware") + " / " + ioc.get("malware_printable", "Unknown"),
                    "source": "ThreatFox",
                    "desc": f"Malicious {ioc.get('ioc_type')} associated with {ioc.get('malware_printable')} threat actor.",
                    "remediation": f"Block IOC ({ioc.get('ioc_value')}) on perimeter firewalls and endpoint security tools."
                })
    except Exception as e:
        print(f"ThreatFox Error: {e}")

def fetch_urlhaus():
    print("Fetching URLhaus Malicious URLs...")
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    
    try:
        response = requests.get(url)
        if response.ok:
            data = response.json().get("urls", [])
            for item in data[:15]: # Grab the latest 15 malicious URLs
                unified_data.append({
                    "id": f"URL-{item.get('id')}",
                    "severity": "HIGH",
                    "date": item.get("date_added", "").split(" ")[0],
                    "product": "Web Traffic",
                    "source": "URLhaus",
                    "desc": f"Malware distribution URL identified. Status: {item.get('url_status')}",
                    "remediation": f"Add to Secure Web Gateway (SWG) blocklist: {item.get('url')}"
                })
    except Exception as e:
        print(f"URLhaus Error: {e}")

if __name__ == "__main__":
    fetch_alienvault()
    fetch_virustotal()
    fetch_threatfox()
    fetch_urlhaus()
    
    # Fallback only triggers if EVERY feed fails
    if len(unified_data) == 0:
        print("All live feeds failed. Writing fallback.")
        unified_data = [{
            "id": "ERR-001",
            "severity": "MEDIUM",
            "date": datetime.today().strftime('%Y-%m-%d'),
            "product": "API Infrastructure",
            "source": "System Monitor",
            "desc": "Failed to reach external OSINT APIs.",
            "remediation": "Check GitHub Actions runner logs."
        }]
        
    os.makedirs("data", exist_ok=True)
    with open("data/auth_intel.json", "w") as f:
        json.dump(unified_data, f, indent=4)