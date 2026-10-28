# scan_tron.py
import os
import json
import requests
import subprocess

# --- CONFIG ---
TRONSCAN_API_KEY = os.environ.get("TRONSCAN_API_KEY", "")
TRONSCAN_API = "https://apilist.tronscanapi.com/api/contracts"
HEADERS = {"TRON-PRO-API-KEY": TRONSCAN_API_KEY} if TRONSCAN_API_KEY else {}

def fetch_recent_contracts(limit=5):
    params = {
        "verified-only": "true",
        "limit": limit,
        "start": 0,
        "sort": "-timestamp",
        "count": "true",
        "confirm": "0",
        "open-source-only": "false",
    }
    r = requests.get(TRONSCAN_API, headers=HEADERS, params=params)
    r.raise_for_status()
    return r.json().get("data", [])

def fetch_bytecode(address):
    url = f"https://apilist.tronscanapi.com/api/contract?contract={address}"
    r = requests.get(url, headers=HEADERS)
    r.raise_for_status()
    data = r.json().get("data", [{}])[0]
    return data.get("bytecode")

def analyze_bytecode(bytecode):
    """Calls the myth CLI tool to analyze the bytecode."""
    if not bytecode:
        return None
    
    # Use the myth command-line tool
    command = [
        "myth", "analyze",
        "-c", bytecode,
        "--execution-timeout", "60",
        "-o", "json"
    ]
    
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=120
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Mythril analysis failed: {e.stderr}")
        return None
    except json.JSONDecodeError:
        print("Failed to parse Mythril JSON output.")
        return None
    except subprocess.TimeoutExpired:
        print("Mythril analysis timed out.")
        return None

def is_ownership_risk(mythril_results):
    """Heuristic to check for ownership/access control risks."""
    if not mythril_results:
        return False
    
    # SWC IDs for access control issues
    risk_swc_ids = {"SWC-105", "SWC-106", "SWC-115"}
    
    for issue in mythril_results:
        for problem in issue.get("issues", []):
            swc_id = problem.get("swc-id")
            if swc_id in risk_swc_ids:
                return True
    return False

def main():
    print("🔍 Starting automated TRON ownership scan...")
    contracts = fetch_recent_contracts(limit=5)
    
    if not contracts:
        print("No contracts found.")
        return

    vulnerable_contracts = []
    
    for contract in contracts:
        address = contract.get("address")
        name = contract.get("name", "Unknown")
        print(f"\n--- Analyzing: {name} ({address}) ---")
        
        bytecode = fetch_bytecode(address)
        if not bytecode:
            print("  ⚠️ No bytecode.")
            continue
            
        print("  🛠️ Running Mythril...")
        results = analyze_bytecode(bytecode)
        
        if results is None:
            print("  ⚠️ Analysis failed.")
            continue
            
        if is_ownership_risk(results):
            print("  🚨 HIGH RISK: Potential access control issue detected!")
            vulnerable_contracts.append({"name": name, "address": address})
        else:
            print("  ✅ No ownership risks detected.")

    # --- Final Report ---
    print("\n" + "="*40)
    print("FINAL SCAN REPORT")
    print("="*40)
    if vulnerable_contracts:
        print(f"Found {len(vulnerable_contracts)} vulnerable contract(s):")
        for c in vulnerable_contracts:
            print(f"  - {c['name']}: {c['address']}")
    else:
        print("No vulnerabilities found.")

    with open("vulnerable_contracts.json", "w") as f:
        json.dump(vulnerable_contracts, f, indent=2)
    print("\nResults saved to vulnerable_contracts.json")

if __name__ == "__main__":
    main()
