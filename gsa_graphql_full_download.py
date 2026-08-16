import requests
import json
import os
import time
from datetime import datetime
from dotenv import load_dotenv

# 1. Load Environment
try:
    load_dotenv(dotenv_path=os.path.expanduser("~/.env"))
except:
    pass

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
if not GITHUB_TOKEN:
    print("❌ ERROR: GITHUB_TOKEN not found in ~/.env")
    exit(1)

FEED_URL = "https://api.github.com/graphql"

# State file to track progress
STATE_FILE = os.path.expanduser("~/.github_advisory_progress.json")
OUTPUT_FILE = os.path.expanduser("~/github_advisories_full.jsonl") # JSON Lines format (one JSON object per line)

# Malware keywords (optional, for filtering later)
MALWARE_KEYWORDS = ["malware", "trojan", "ransomware", "backdoor", "infostealer"]

def get_malware_keywords(description):
    if not description: return []
    desc = description.lower()
    return [kw for kw in MALWARE_KEYWORDS if kw in desc]

def load_progress():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    return {"last_cursor": None, "total_fetched": 0}

def save_progress(cursor, total_fetched):
    with open(STATE_FILE, 'w') as f:
        json.dump({"last_cursor": cursor, "total_fetched": total_fetched}, f)

def fetch_page(cursor=None):
    """Fetches a single page of 100 items."""
    # Construct query with cursor
    query = """
    query($cursor: String, $first: Int!) {
        securityVulnerabilities(first: $first, orderBy: {field: UPDATED_AT, direction: DESC}, after: $cursor) {
            edges {
                cursor
                node {
                    package { name ecosystem }
                    severity
                    firstPatchedVersion { identifier }
                    advisory {
                        ghsaId
                        description
                        publishedAt
                        updatedAt
                        references(first: 1) { url }
                        cwes(first: 10) { nodes { id name } }
                    }
                }
            }
            pageInfo {
                hasNextPage
                endCursor
            }
        }
    }
    """
    
    variables = {"first": 100, "cursor": cursor} if cursor else {"first": 100}
    
    try:
        response = requests.post(
            FEED_URL,
            json={"query": query, "variables": variables},
            headers={"Authorization": f"Bearer {GITHUB_TOKEN}", "Content-Type": "application/json"},
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 403:
            # Rate limit hit
            return {"error": "rate_limit", "data": None}
        else:
            return {"error": "http_error", "data": None, "status": response.status_code}
            
    except Exception as e:
        return {"error": "network_error", "data": None, "message": str(e)}

def download_all_advisories():
    print("🚀 Starting Full Historical Download...")
    print(f"   Token Status: {'Valid' if GITHUB_TOKEN else 'Missing'}")
    
    progress = load_progress()
    start_cursor = progress.get("last_cursor")
    total_fetched = progress.get("total_fetched", 0)
    
    # Open file for appending
    file_mode = 'w' if total_fetched == 0 else 'a'
    
    # Check if file exists and has content
    if os.path.exists(OUTPUT_FILE):
        # Count existing lines to verify start point
        with open(OUTPUT_FILE, 'r') as f:
            existing_lines = sum(1 for _ in f)
        if existing_lines > 0:
            print(f"   Resuming from {existing_lines} existing records...")
    
    page_count = 0
    last_error_count = 0
    
    while True:
        page_count += 1
        print(f"\n📄 Fetching Page {page_count} (Total Fetched: {total_fetched})...")
        
        result = fetch_page(start_cursor)
        
        if "error" in result:
            if result["error"] == "rate_limit":
                print("⚠️ Rate limit hit. Waiting 60 seconds...")
                time.sleep(60)
                last_error_count += 1
                if last_error_count > 3:
                    print("❌ Too many rate limit errors. Stopping.")
                    break
                continue
            else:
                print(f"❌ Error: {result['error']}")
                time.sleep(5)
                continue
        
        data = result["data"]
        vulns = data["securityVulnerabilities"]
        edges = vulns["edges"]
        page_info = vulns["pageInfo"]
        
        if not edges:
            print("✅ Finished! No more pages.")
            break
        
        # Process items
        new_count = 0
        for edge in edges:
            node = edge["node"]
            ghsa_id = node["advisory"]["ghsaId"]
            
            # Check if already saved (simple check by ID)
            # To be safe, we rely on the cursor, but let's add a quick ID check
            # (Optional: Skip if ID already in file to prevent duplicates if script restarts mid-batch)
            
            # Add metadata
            node["fetched_at"] = datetime.now().isoformat()
            node["keywords"] = get_malware_keywords(node["advisory"].get("description", ""))
            
            # Write to file (JSON Lines)
            with open(OUTPUT_FILE, 'a') as f:
                f.write(json.dumps(node) + "\n")
            
            total_fetched += 1
            new_count += 1
        
        print(f"   ✅ Processed {new_count} items. Total: {total_fetched}")
        
        # Save progress
        save_progress(page_info["endCursor"], total_fetched)
        
        # Move to next page
        start_cursor = page_info["endCursor"]
        
        if not page_info["hasNextPage"]:
            print("✅ Finished! No more pages.")
            break
        
        # Safety Delay to respect rate limits (2 seconds between requests)
        time.sleep(2)
        last_error_count = 0

    print(f"\n🏁 Download Complete!")
    print(f"   Total Historical Advisories Downloaded: {total_fetched}")
    print(f"   Output File: {OUTPUT_FILE}")

if __name__ == "__main__":
    download_all_advisories()
