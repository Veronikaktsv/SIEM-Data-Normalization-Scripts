import json
import re

def parse_firewall_line(line):
    # Example Cisco ASA log (simplified)
    # Example: "2025-08-12T14:12:30Z ASA FW: SRC=10.0.0.1 DST=8.8.8.8 SPT=12345 DPT=53 PROTO=UDP"
    pattern = r'(?P<timestamp>\S+) ASA FW: SRC=(?P<src_ip>\S+) DST=(?P<dst_ip>\S+) SPT=(?P<src_port>\d+) DPT=(?P<dst_port>\d+) PROTO=(?P<protocol>\S+)'
    match = re.match(pattern, line)
    if not match:
        return None
    data = match.groupdict()
    # Normalize keys
    return {
        "timestamp": data["timestamp"],
        "event_source": "firewall",
        "src_ip": data["src_ip"],
        "dst_ip": data["dst_ip"],
        "src_port": int(data["src_port"]),
        "dst_port": int(data["dst_port"]),
        "protocol": data["protocol"],
        "event_type": "network-connection",
        "severity": "medium"
    }

def normalize_firewall_log(input_file, output_file):
    normalized_logs = []
    with open(input_file) as f:
        for line in f:
            parsed = parse_firewall_line(line.strip())
            if parsed:
                normalized_logs.append(parsed)
    with open(output_file, 'w') as out:
        for entry in normalized_logs:
            out.write(json.dumps(entry) + '\n')

if __name__ == "__main__":
    normalize_firewall_log("raw_logs/firewall.log", "normalized_logs/firewall_normalized.json")
