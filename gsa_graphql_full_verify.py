import json

malware_count = 0
total_count = 0

with open("github_advisories_full.jsonl", "r") as f:
    for line in f:
        data = json.loads(line)
        total_count += 1
        if "malware" in data.get("keywords", []):
            malware_count += 1

print(f"Total: {total_count}, Malware: {malware_count}")
