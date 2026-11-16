
import json
import re


def load_rules(filename="rules.json"):
    """Load detection signatures from JSON file."""
    try:
        with open(filename, "r", encoding="utf-8") as file:
            data = json.load(file)
        return data.get("rules", [])
    except (FileNotFoundError, json.JSONDecodeError) as error:
        print(f"[ERROR] Could not load rules: {error}")
        return []


def detect_suspicious_traffic(payload, rules):
    """Match network payload against detection signatures."""
    alerts = []

    for rule in rules:
        pattern = re.escape(rule["pattern"])

        if re.search(pattern, payload, re.IGNORECASE):
            alerts.append({
                "rule_id": rule["id"],
                "name": rule["name"],
                "severity": rule["severity"],
                "matched_pattern": rule["pattern"]
            })

    return alerts
