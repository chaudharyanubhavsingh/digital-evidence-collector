import json

def collect_evidence(data):
    with open("evidence.json", "a") as f:
        json.dump(data, f)
        f.write("\n")