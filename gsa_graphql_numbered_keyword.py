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

# Keywords to look for
MALWARE_KEYWORDS = [
    "malware", "trojan", "ransomware", "backdoor", "infostealer", 
    "keylogger", "cryptominer", "botnet", "worm", "spyware", 
    "adware", "rootkit", "exploit", "injection", "command and control",
    "c2", "cobalt strike", "mimikatz", "empire"
]

def get_malware_keywords(description):
    """Returns a list of matching keywords found in the description."""
    desc = (description or "").lower()
    found = [kw for kw in MALWARE_KEYWORDS if kw in desc]
    return found

def fetch_advisories():
    if not GITHUB_TOKEN:
        print("❌ ERROR: No GitHub Token found.")
        return

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Content-Type": "application/json"
    }

    try:
        print("🔍 Fetching security vulnerabilities...")
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

        print(f"✅ Fetched {len(nodes)} advisories.\n")
        print("-" * 100)
        print(f"{'#':<4} | {'GHSA ID':<20} | {'Package':<20} | {'Severity':<10} | {'Date':<20} | {'Type':<10} | {'Keywords'}")
        print("-" * 100)

        for i, vuln in enumerate(nodes, start=1):
            pkg = vuln['package']
            adv = vuln['advisory']
            gh_id = adv['ghsaId']
            published = adv['publishedAt']
            severity = vuln['severity']
            desc = adv['description']

            # Determine Type and find keywords
            found_keywords = get_malware_keywords(desc)
            
            if found_keywords:
                # Join keywords with commas (e.g., "trojan, malware")
                keyword_str = ", ".join(found_keywords)
                type_display = "[MALWARE]"
                # Optional: Color the Type column if it's malware
                type_display = f"\033[91m{type_display}\033[0m"
            else:
                keyword_str = "-"
                type_display = "[GENERAL]"

            # Format output
            # Column 1: Just the number (1, 2, 3...)
            # Column 7: The specific keywords found
            print(f"{i:<4} | {gh_id:<20} | {pkg['name']:<20} | {severity:<10} | {published:<20} | {type_display:<10} | {keyword_str}")

        print("-" * 100)

        # Save to JSON
        save_to_json(nodes)

    except Exception as e:
        print(f"❌ Error: {e}")

def save_to_json(data):
    filename = f"advisories_clean_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print(f"\n💾 Data saved to: {filename}")
    except Exception as e:
        print(f"❌ Save error: {e}")

if __name__ == "__main__":
    fetch_advisories()
