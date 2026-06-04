import os
import requests
import json
from datetime import datetime

# 1. Securely load API keys from GitHub Secrets
VT_KEY = os.environ.get("VT_API_KEY")
OTX_KEY = os.environ.get("OTX_API_KEY")

unified_data = []

def fetch_alienvault():
    if not OTX_KEY:
        print("Skipping OTX: No API key found.")
        return
        
    print("Fetching AlienVault OTX Pulses...")
    headers = {"X-OTX-API-KEY": OTX_KEY}
    # Fetching recently modified threat pulses
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=10"
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        pulses = response.json().get("results", [])
        
        for pulse in pulses:
            unified_data.append({
                "id": pulse.get("id")[:8] + " (OTX)",
                "severity": "HIGH", # OTX pulses usually represent active threat campaigns
                "date": pulse.get("modified", "").split("T")[0],
                "product": "Various Endpoints",
                "source": "AlienVault OTX",
                "desc": pulse.get("name", "Unknown Threat Campaign"),
                "remediation": "Review OTX pulse indicators (IOCs) and block associated IPs/Domains at the perimeter."
            })
    except Exception as e:
        print(f"OTX Error: {e}")

def fetch_virustotal():
    if not VT_KEY:
        print("Skipping VirusTotal: No API key found.")
        return
        
    print("Fetching VirusTotal Intelligence...")
    headers = {
        "accept": "application/json",
        "x-apikey": VT_KEY
    }
    # Example: Fetching popular threat actors or a specific collection
    # Note: VT API v3 requires precise endpoint targeting. This uses a placeholder search 
    # for recent high-profile collections as an example.
    url = "https://www.virustotal.com/api/v3/collections?limit=5"
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        collections = response.json().get("data", [])
        
        for item in collections:
            attrs = item.get("attributes", {})
            unified_data.append({
                "id": item.get("id", "VT-Collection")[:10],
                "severity": "CRITICAL",
                "date": datetime.today().strftime('%Y-%m-%d'),
                "product": "Targeted Campaign",
                "source": "VirusTotal",
                "desc": attrs.get("name", "Malware Campaign Identified"),
                "remediation": "Hunt for provided file hashes in EDR and block network communications."
            })
    except Exception as e:
        print(f"VT Error: {e}")

if __name__ == "__main__":
    fetch_alienvault()
    fetch_virustotal()
    
    # Ensure the data directory exists
    os.makedirs("data", exist_ok=True)
    
    # Write the unified intel to a local JSON file
    with open("data/auth_intel.json", "w") as f:
        json.dump(unified_data, f, indent=4)
    
    print(f"Successfully wrote {len(unified_data)} records to data/auth_intel.json")