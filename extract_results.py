import json
import re

with open('ai_results.json', 'r', encoding='utf-8') as f:
    for line in f:
        match = re.search(r'(\{.*\})', line)
        if match:
            try:
                data = json.loads(match.group(1))
                results = data.get('results', [])
                print(f"Scan ID: {data.get('scan_id')}, Total Findings: {data.get('total_findings')}, Results count: {len(results)}")
                if len(results) > 0:
                    print(json.dumps(data, indent=2)[:3000])
                    break
            except Exception as e:
                pass
