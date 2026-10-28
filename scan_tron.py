import os
import json
import requests
import subprocess
import re
import time
from solcx import install_solc, compile_standard

# --- CONFIG ---
TRONSCAN_API_KEY = os.environ.get("TRONSCAN_API_KEY", "")
TRONSCAN_API = "https://apilist.tronscanapi.com/api/contracts"
HEADERS = {"TRON-PRO-API-KEY": TRONSCAN_API_KEY} if TRONSCAN_API_KEY else {}

if not TRONSCAN_API_KEY:
    print("⚠️ WARNING: No TRONSCAN_API_KEY found in environment variables. You will likely be rate-limited!")

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
    try:
        r = requests.get(TRONSCAN_API, headers=HEADERS, params=params)
        r.raise_for_status()
        return r.json().get("data", [])
    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to fetch contracts: {e}")
        return []

def fetch_source_code(address):
    url = f"https://apilist.tronscanapi.com/api/contract?contract={address}"
    try:
        r = requests.get(url, headers=HEADERS)
        if r.status_code == 429:
            print("  ⚠️ Rate limited by Tronscan (429). Waiting 5 seconds...")
            time.sleep(5)
            return None
        r.raise_for_status()
        data = r.json().get("data", [{}])[0]
        source = data.get("code")
        if source and source.startswith("{"):
            try:
                parsed = json.loads(source)
                source = list(parsed.get("sources", {}).values())[0].get("content", "")
            except:
                pass
        return source
    except Exception as e:
        print(f"  ⚠️ Error fetching source: {e}")
        return None

def get_solc_version(source_code):
    match = re.search(r'pragma\s+solidity\s+([^;]+);', source_code)
    if match:
        version_str = match.group(1).strip()
        version_match = re.search(r'(\d+\.\d+\.\d+)', version_str)
        if version_match:
            return version_match.group(1)
    return "0.8.19"

def compile_source_to_bytecode(source_code):
    if not source_code:
        return None

    solc_version = get_solc_version(source_code)
    print(f"  🛠️ Using solc version {solc_version}...")

    try:
        install_solc(solc_version)
        compiled = compile_standard(
            {
                "language": "Solidity",
                "sources": {"contract.sol": {"content": source_code}},
                "settings": {"outputSelection": {"*": {"*": ["evm.bytecode.object"]}}},
            },
            solc_version=solc_version,
        )
        
        bytecode = compiled["contracts"]["contract.sol"]
        for contract_name, contract_data in bytecode.items():
            return contract_data["evm"]["bytecode"]["object"]
        return None
    except Exception as e:
        print(f"  ⚠️ Compilation failed: {e}")
        return None

def analyze_bytecode(bytecode):
    if not bytecode:
        return None

    command = [
        "docker", "run", "--rm",
        "mythril/myth",
        "myth", "analyze",
        "-c", bytecode,
        "--execution-timeout", "60",
        "-o", "json"
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=120)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"  ⚠️ Mythril failed.")
        return None
    except Exception:
        return None

def is_ownership_risk(mythril_results):
    if not mythril_results:
        return False
    risk_swc_ids = {"SWC-105", "SWC-106", "SWC-115"}
    for issue in mythril_results:
        for problem in issue.get("issues", []):
            if problem.get("swc-id") in risk_swc_ids:
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

        source = fetch_source_code(address)
        
        # Wait 2 seconds before making the next API call to avoid rate limits
        time.sleep(2)

        if not source:
            print("  ⚠️ No source code available.")
            continue

        print("  🛠️ Compiling source to bytecode...")
        bytecode = compile_source_to_bytecode(source)
        if not bytecode:
            continue

        print("  🛠️ Running Mythril on bytecode...")
        results = analyze_bytecode(bytecode)

        if is_ownership_risk(results):
            print("  🚨 HIGH RISK: Potential access control issue detected!")
            vulnerable_contracts.append({"name": name, "address": address})
        else:
            print("  ✅ No ownership risks detected.")

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
