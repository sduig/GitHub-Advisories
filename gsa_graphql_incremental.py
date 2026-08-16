import requests
import json
import os
from datetime import datetime

# 1. Correct Import for python-dotenv
try:
    from dotenv import load_dotenv
except ImportError:
    print("❌ ERROR: 'python-dotenv' library is not installed.")
    print("   Run: pip install python-dotenv")
    exit(1)

# Configuration
HOME_DIR = os.path.expanduser("~")
ENV_FILE_PATH = os.path.join(HOME_DIR, ".env")
STATE_FILE = os.path.join(HOME_DIR, ".github_advisory_state.json")

if os.path.exists(ENV_FILE_PATH):
    load_dotenv(dotenv_path=ENV_FILE_PATH)

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
FEED_URL = "https://api.github.com/graphql"

QUERY_ALL = """
query {
  securityVulnerabilities(first: 50, orderBy: {field: UPDATED_AT, direction: DESC}) {
    nodes {
      package { name ecosystem }
      severity
      firstPatchedVersion { identifier }
      advisory {
        ghsaId
        description
        publishedAt
        updatedAt
        references { url }
        cwes(first: 10) { nodes { id name } }
      }
    }
  }
}
"""

MALWARE_KEYWORDS = [
    "malware", "trojan", "ransomware", "backdoor", "infostealer", 
    "keylogger", "cryptominer", "botnet", "worm", "spyware", 
    "adware", "rootkit", "exploit", "injection", "command and control",
    "c2", "cobalt strike", "mimikatz", "empire"
]

def get_malware_keywords(description):
    desc = (description or "").lower()
    return [kw for kw in MALWARE_KEYWORDS if kw in desc]

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {"last_ids": [], "last_date": None}
    return {"last_ids": [], "last_date": None}

def save_state(state):
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=4)

def fetch_advisories():
    if not GITHUB_TOKEN:
        print("❌ ERROR: No GitHub Token found.")
        return

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Content-Type": "application/json"
    }

    # Load previous state
    state = load_state()
    last_ids = set(state.get("last_ids", []))
    last_date = state.get("last_date")

    try:
        print("🔍 Fetching recent security vulnerabilities...")
        response = requests.post(FEED_URL, json={"query": QUERY_ALL}, headers=headers, timeout=60)

        if response.status_code != 200:
            print(f"❌ Failed: {response.status_code}")
            return

        data = response.json()
        if "errors" in data:
            print(f"❌ API Error: {data['errors']}")
            return

        nodes = data["data"]["securityVulnerabilities"]["nodes"]
        
        # Ensure sorted by date (most recent first)
        nodes.sort(key=lambda x: x['advisory']['publishedAt'], reverse=True)

        new_advisories = []

        # Filter for NEW advisories only
        for i, vuln in enumerate(nodes, start=1):
            gh_id = vuln['advisory']['ghsaId']
            
            # If ID is NOT in the last_ids set, it's a new one
            if gh_id not in last_ids:
                new_advisories.append({
                    "rank": i,
                    "node": vuln
                })

        # If no new advisories, just update the timestamp and exit
        if not new_advisories:
            print("✅ No new advisories found since last run.")
            # Update state just in case dates changed
            state["last_ids"] = [v['advisory']['ghsaId'] for v in nodes]
            state["last_date"] = datetime.now().isoformat()
            save_state(state)
            return

        # Process and Print New Advisories
        print(f"✅ Found {len(new_advisories)} NEW advisories.\n")
        print("-" * 100)
        print(f"{'#':<4} | {'GHSA ID':<20} | {'Package':<20} | {'Severity':<10} | {'Date':<20} | {'Type':<10} | {'Keywords'}")
        print("-" * 100)

        for item in new_advisories:
            vuln = item['node']
            i = item['rank'] # Keep original rank (1=most recent overall)
            
            pkg = vuln['package']
            adv = vuln['advisory']
            gh_id = adv['ghsaId']
            published = adv['publishedAt']
            severity = vuln['severity']
            desc = adv['description']

            found_keywords = get_malware_keywords(desc)
            
            if found_keywords:
                keyword_str = ", ".join(found_keywords)
                type_display = f"\033[91m[MALWARE]\033[0m"
            else:
                keyword_str = "-"
                type_display = "[GENERAL]"

            print(f"{i:<4} | {gh_id:<20} | {pkg['name']:<20} | {severity:<10} | {published:<20} | {type_display:<10} | {keyword_str}")

        print("-" * 100)
        
        # Save NEW advisories to a separate file for easy review
        save_new_advisories(new_advisories)

        # Update State
        # We save the IDs of ALL fetched items (or just the new ones? 
        # Best practice: Save IDs of the latest batch fetched to avoid re-fetching next time)
        # Here we save the IDs of the *current* batch to prevent duplicates.
        current_ids = [v['advisory']['ghsaId'] for v in nodes]
        state["last_ids"] = current_ids
        state["last_date"] = datetime.now().isoformat()
        save_state(state)

        print(f"💾 State updated. Next run will check for new items.")

    except Exception as e:
        print(f"❌ Error: {e}")

def save_new_advisories(new_advisories):
    filename = f"new_advisories_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            # Extract just the nodes for the JSON
            raw_nodes = [item['node'] for item in new_advisories]
            json.dump(raw_nodes, f, indent=4, ensure_ascii=False)
        print(f"💾 New advisories saved to: {filename}")
    except Exception as e:
        print(f"❌ Save error: {e}")

if __name__ == "__main__":
    fetch_advisories()
