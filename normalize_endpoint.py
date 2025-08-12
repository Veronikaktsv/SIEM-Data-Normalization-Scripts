import json
import re

def parse_endpoint_line(line):
    # Example simplified Windows Event Log entry
    # 2025-08-12T12:00:00Z Security EventID=4624 User=DOMAIN\User1 SrcIp=10.1.1.5
    pattern = r'(?P<timestamp>\S+) Security EventID=(?P<event_id>\d+) User=(?P<user>\S+) SrcIp=(?P<src_ip>\S+)'
    match = re.match(pattern, line)
    if not match:
        return None
    data = match.groupdict()
    return {
        "timestamp": data["timestamp"],
        "event_source": "endpoint",
        "user": data["user"],
        "src_ip": data["src_ip"],
        "event_type": "login",
        "event_id": int(data["event_id"]),
        "severity": "medium"
    }

def normalize_endpoint_log(input_file, output_file):
    normalized_logs = []
    with open(input_file) as f:
        for line in f:
            parsed = parse_endpoint_line(line.strip())
            if parsed:
                normalized_logs.append(parsed)
    with open(output_file, 'w') as out:
        for entry in normalized_logs:
            out.write(json.dumps(entry) + '\n')

if __name__ == "__main__":
    normalize_endpoint_log("raw_logs/endpoint.log", "normalized_logs/endpoint_normalized.json")
