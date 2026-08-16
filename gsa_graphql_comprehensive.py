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

# Load the .env file manually
if os.path.exists(ENV_FILE_PATH):
    load_dotenv(dotenv_path=ENV_FILE_PATH)

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
FEED_URL = "https://api.github.com/graphql"

# --- Query: All Vulnerabilities (No type filter) ---
QUERY_ALL = """
query {
  securityVulnerabilities(first: 100, orderBy: {field: UPDATED_AT, direction: DESC}) {
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

# Keywords to identify Malware in descriptions
MALWARE_KEYWORDS = [
    "malware", "trojan", "ransomware", "backdoor", "infostealer", 
    "keylogger", "cryptominer", "botnet", "worm", "spyware", 
    "adware", "rootkit", "exploit", "injection", "command and control",
    "c2", "cobalt strike", "mimikatz", "empire"
]

def is_malware(advisory):
    """Check if the advisory description contains malware keywords."""
    description = advisory.get('description', '').lower()
    return any(keyword in description for keyword in MALWARE_KEYWORDS)

def fetch_advisories():
    if not GITHUB_TOKEN:
        print("❌ ERROR: No GitHub Token found.")
        print("   Please add 'GITHUB_TOKEN=your_token' to your ~/.env file")
        return

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Content-Type": "application/json"
    }

    all_vulnerabilities = []
    seen_ids = set()

    try:
        print("🔍 Fetching all security vulnerabilities...")
        response = requests.post(FEED_URL, json={"query": QUERY_ALL}, headers=headers, timeout=60)

        if response.status_code == 200:
            data = response.json()
            
            if "errors" in data:
                print(f"❌ API Error: {data['errors']}")
                return
            
            nodes = data["data"]["securityVulnerabilities"]["nodes"]
            
            for node in nodes:
                gh_id = node['advisory']['ghsaId']
                if gh_id not in seen_ids:
                    # Determine Type
                    advisory = node['advisory']
                    if is_malware(advisory):
                        node['type'] = "MALWARE"
                    else:
                        node['type'] = "GENERAL"
                    
                    all_vulnerabilities.append(node)
                    seen_ids.add(gh_id)

            if not all_vulnerabilities:
                print("⚠️ No advisories found.")
                return

            # Sort by date
            all_vulnerabilities.sort(key=lambda x: x['advisory']['publishedAt'], reverse=True)

            malware_count = sum(1 for v in all_vulnerabilities if v['type'] == 'MALWARE')
            general_count = len(all_vulnerabilities) - malware_count

            print(f"✅ Total Combined: {len(all_vulnerabilities)}")
            print(f"   - MALWARE: {malware_count}")
            print(f"   - GENERAL: {general_count}")

            # Print Header
            print(f"{'GHSA ID':<20} {'Package':<20} {'Severity':<10} {'Published':<20} {'Type'}")
            print("-" * 100)

            for vuln in all_vulnerabilities:
                pkg = vuln['package']
                adv = vuln['advisory']
                gh_id = adv['ghsaId']
                published = adv['publishedAt']
                severity = vuln['severity']
                v_type = vuln['type']
                
                # Color coding
                if v_type == "MALWARE":
                    type_display = f"\033[91m[{v_type}]\033[0m" # Red
                else:
                    type_display = f"[{v_type}]"

                print(f"{gh_id:<20} {pkg['name']:<20} ({pkg['ecosystem']}) {severity:<10} {published:<20} {type_display}")

            save_to_json(all_vulnerabilities)

        else:
            print(f"❌ Failed to fetch data. Status Code: {response.status_code}")
            print(f"Response: {response.text}")

    except Exception as e:
        print(f"❌ An error occurred: {e}")

def save_to_json(data):
    filename = f"comprehensive_advisories_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print(f"\n💾 Data saved to: {filename}")
    except Exception as e:
        print(f"❌ Error saving file: {e}")

if __name__ == "__main__":
    fetch_advisories()
