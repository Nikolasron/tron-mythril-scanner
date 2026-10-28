# scan_tron.py
import os
import json
import requests
from mythril.mythril import Mythril
from detector import OwnershipTakeoverDetector

# ─── CONFIG ───────────────────────────────────────────────
TRONSCAN_API_KEY = os.environ.get("TRONSCAN_API_KEY", "")
TRONSCAN_API = "https://apilist.tronscanapi.com/api/contracts"
HEADERS = {"TRON-PRO-API-KEY": TRONSCAN_API_KEY} if TRONSCAN_API_KEY else {}

# ─── FETCH CONTRACTS ──────────────────────────────────────
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

# ─── RUN MYTHRIL ──────────────────────────────────────────
def analyze_bytecode(bytecode):
    # Initialize Mythril with the custom plugin
    mythril = Mythril(
        solc_version=None,
        dynld=False,
        onchain_storage_access=True,
        enable_plugins=[OwnershipTakeoverDetector()]
    )
    
    # Run symbolic execution
    mythril.fire_lasers(
        contract=None,
        bytecode=bytecode,
        max_depth=128,
        execution_timeout=120,
    )
    
    # Collect issues
    issues = mythril.execution_info.get_issues()
    return issues

# ─── MAIN AUTOMATED LOOP ──────────────────────────────────
def main():
    print("🔍 Starting automated TRON ownership takeover scan...")
    contracts = fetch_recent_contracts(limit=5)

    if not contracts:
        print("No contracts found to analyze.")
        return

    vulnerable_contracts = []

    for contract in contracts:
        address = contract.get("address")
        name = contract.get("name", "Unknown")
        print(f"\n--- Analyzing: {name} ({address}) ---")

        bytecode = fetch_bytecode(address)
        if not bytecode:
            print("  ⚠️ Skipping: No bytecode.")
            continue

        print("  🛠️ Running Mythril...")
        try:
            issues = analyze_bytecode(bytecode)
        except Exception as e:
            print(f"  ⚠️ Analysis failed: {e}")
            continue

        if issues:
            print(f"  🚨 FOUND {len(issues)} ISSUE(S)!")
            for issue in issues:
                print(f"     - {issue.title}: {issue.description_head}")
            vulnerable_contracts.append({
                "address": address,
                "name": name,
                "issues": [i.title for i in issues]
            })
        else:
            print("  ✅ No ownership takeover issues detected.")

    # ─── FINAL REPORT ─────────────────────────────────────
    print("\n" + "=" * 50)
    print("FINAL SCAN REPORT")
    print("=" * 50)
    if vulnerable_contracts:
        print(f"Found {len(vulnerable_contracts)} vulnerable contract(s):")
        for v in vulnerable_contracts:
            print(f"  - {v['name']}: {v['address']}")
    else:
        print("No ownership takeover vulnerabilities found in this batch.")

    # Save to file for your dashboard
    with open("vulnerable_contracts.json", "w") as f:
        json.dump(vulnerable_contracts, f, indent=2)
    print("\nResults saved to vulnerable_contracts.json")

if __name__ == "__main__":
    main()
