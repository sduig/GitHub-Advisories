import json
import os
import boto3
import requests
from datetime import datetime, timezone
from urllib.parse import quote

# Initialize clients
dynamodb = boto3.client('dynamodb')
s3 = boto3.client('s3')
S3_BUCKET = os.environ['S3_BUCKET_NAME']
DYNAMODB_TABLE = os.environ['DYNAMODB_TABLE']
GITHUB_TOKEN = os.environ['GITHUB_TOKEN']

# Configuration
FEED_URL = "https://api.github.com/graphql"
MAX_ITEMS_PER_RUN = 50  # Keep this low to stay within 15m timeout and rate limits

# Malware keywords
MALWARE_KEYWORDS = [
    "malware", "trojan", "ransomware", "backdoor", "infostealer", 
    "keylogger", "cryptominer", "botnet", "worm", "spyware", 
    "adware", "rootkit", "exploit", "injection", "command and control",
    "c2", "cobalt strike", "mimikatz", "empire"
]

def get_malware_keywords(description):
    if not description: return []
    desc = description.lower()
    return [kw for kw in MALWARE_KEYWORDS if kw in desc]

def lambda_handler(event, context):
    print("🚀 Starting Lambda Execution...")
    
    try:
        # 1. Get Last Seen Timestamp from DynamoDB
        last_seen_response = dynamodb.get_item(
            TableName=DYNAMODB_TABLE,
            Key={'PK': {'S': 'CONFIG'}, 'SK': {'S': 'LAST_SEEN'}}
        )
        
        last_seen_ts = None
        if 'Item' in last_seen_response:
            last_seen_ts = last_seen_response['Item']['last_ts']['S']
            print(f"📅 Last run timestamp: {last_seen_ts}")
        else:
            print("🆕 First run detected. Fetching initial batch...")
            last_seen_ts = datetime.now(timezone.utc).isoformat()

        # 2. Fetch New Advisories
        # We fetch items ordered by UPDATED_AT DESC. 
        # We will filter client-side for items newer than last_seen_ts 
        # because GitHub's query doesn't support "WHERE updatedAt > X" directly in a simple way.
        # We fetch a batch (e.g., 100) and filter.
        
        query = """
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
                        references(first: 1) { url }
                        cwes(first: 10) { nodes { id name } }
                    }
                }
            }
        }
        """
        
        headers = {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Content-Type": "application/json"
        }
        
        response = requests.post(FEED_URL, json={"query": query}, headers=headers, timeout=30)
        
        if response.status_code != 200:
            print(f"❌ API Error: {response.status_code}")
            return {'statusCode': response.status_code, 'body': 'API Error'}
        
        data = response.json()
        if "errors" in data:
            print(f"❌ GraphQL Error: {data['errors']}")
            return {'statusCode': 500, 'body': 'GraphQL Error'}
        
        nodes = data["data"]["securityVulnerabilities"]["nodes"]
        
        # Filter for NEW items (newer than last_seen_ts)
        new_items = []
        newest_timestamp = last_seen_ts
        
        for node in nodes:
            updated_at = node['advisory']['updatedAt']
            # Compare timestamps (ISO format strings work for lexicographical comparison if formatted correctly)
            if updated_at > last_seen_ts:
                # Enrich with metadata
                node['keywords'] = get_malware_keywords(node['advisory'].get('description', ''))
                node['fetched_at'] = datetime.now(timezone.utc).isoformat()
                new_items.append(node)
                
                # Track the newest timestamp found in this batch
                if updated_at > newest_timestamp:
                    newest_timestamp = updated_at
        
        # 3. Save Results
        if new_items:
            print(f"✅ Found {len(new_items)} new advisories.")
            
            # Generate filename
            timestamp_str = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
            s3_key = f"advisories/{timestamp_str}_new.jsonl"
            
            # Write to S3 (JSON Lines format)
            s3_content = ""
            for item in new_items:
                s3_content += json.dumps(item) + "\n"
            
            s3.put_object(
                Bucket=S3_BUCKET,
                Key=s3_key,
                Body=s3_content,
                ContentType='application/x-json-lines'
            )
            print(f"💾 Saved {len(new_items)} items to S3: {s3_key}")
            
            # 4. Update DynamoDB State
            dynamodb.put_item(
                TableName=DYNAMODB_TABLE,
                Item={
                    'PK': {'S': 'CONFIG'},
                    'SK': {'S': 'LAST_SEEN'},
                    'last_ts': {'S': newest_timestamp}
                }
            )
            print(f"📝 Updated last seen timestamp to: {newest_timestamp}")
            
        else:
            print("✅ No new advisories found.")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Success',
                'new_items_found': len(new_items),
                's3_key': s3_key if new_items else None
            })
        }

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
