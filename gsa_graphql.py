import requests
import json
import os
from datetime import dotenv

# Load .env from home directory
# We construct the path to ~/.env
HOME_DIR = os.path.expanduser("~")
ENV_FILE_PATH = os.path.join(HOME_DIR, ".env")

# Load variables from the file if it exists
if os.path.exists(ENV_FILE_PATH):
    dotenv.load_dotenv(ENV_FILE_PATH)
    # print(f"ℹ️  Loaded environment variables from {ENV_FILE_PATH}")

# Configuration
# Fallback: Checks .env first, then system environment variables
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

FEED_URL = "https://api.github.com/graphql"

# GraphQL Query
QUERY = """
query {
  securityVulnerabilities(first: 20, orderBy: {field: UPDATED_AT, direction: DESC}) {
    nodes {
      package {
        name
        ecosystem
      }
      vulnerabilityId
      severity
      description
      publishedAt
      updatedAt
      references {
        url
      }
      cwes {
        cweId
        name
      }
    }
  }
}
"""

def fetch_advisories():
    if not GITHUB_TOKEN:
        print("❌ ERROR: No GitHub Token found.")
        print("   Please add 'GITHUB_TOKEN=your_token' to your ~/.env file")
        print("   Or export GITHUB_TOKEN=your_token in your terminal.")
        return

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Content-Type": "application/json"
    }

    try:
        print(f"🔐 Authenticating with GitHub API...")
        response = requests.post(FEED_URL, json={"query": QUERY}, headers=headers, timeout=30)

        if response.status_code == 200:
            data = response.json()
            
            if "errors" in data:
                print(f"❌ API Error: {data['errors']}")
                return
            
            vulnerabilities = data["data"]["securityVulnerabilities"]["nodes"]
            
            if not vulnerabilities:
                print("⚠️ No vulnerabilities found or API returned empty data.")
                return

            print(f"✅ Successfully fetched {len(vulnerabilities)} advisories.\n")

            # Process and Print Data
            print(f"{'ID':<25} {'Package':<20} {'Severity':<10} {'Published':<20} {'Description (Truncated)'}")
            print("-" * 100)

            for vuln in vulnerabilities:
                pkg_name = vuln['package']['name']
                pkg_eco = vuln['package']['ecosystem']
                vuln_id = vuln['vulnerabilityId']
                severity = vuln['severity']
                published = vuln['publishedAt']
                desc = (vuln['description'][:50] + "...") if len(vuln['description']) > 50 else vuln['description']
                
                print(f"{vuln_id:<25} {pkg_name:<20} ({pkg_eco}) {severity:<10} {published:<20} {desc}")

            # Optional: Save to JSON file
            save_to_json(data)

        else:
            print(f"❌ Failed to fetch data. Status Code: {response.status_code}")
            if response.status_code == 401:
                print("   -> Invalid Token or Token expired. Check your ~/.env file.")
            elif response.status_code == 403:
                print("   -> Rate limit exceeded or permissions missing.")
            print(f"Response: {response.text}")

    except Exception as e:
        print(f"❌ An error occurred: {e}")

def save_to_json(data):
    filename = f"advisories_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print(f"\n💾 Data saved to: {filename}")
    except Exception as e:
        print(f"❌ Error saving file: {e}")

if __name__ == "__main__":
    fetch_advisories()
