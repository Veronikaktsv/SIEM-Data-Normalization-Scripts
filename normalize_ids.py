import json
import re

def parse_ids_line(line):
    # Snort-like alert example
    # [**] [1:1000001:0] SQL Injection Attempt [**] [Priority: 1] {TCP} 192.168.1.2:1234 -> 10.0.0.5:80
    pattern = r'\[\*\*\] \[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\] (?P<message>.+) \[\*\*\] \[Priority: (?P<priority>\d+)\] \{(?P<protocol>\S+)\} (?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)'
    match = re.match(pattern, line)
    if not match:
        return None
    data = match.groupdict()
    return {
        "timestamp": None,
        "event_source": "ids",
        "src_ip": data["src_ip"],
        "dst_ip": data["dst_ip"],
        "src_port": int(data["src_port"]),
        "dst_port": int(data["dst_port"]),
        "protocol": data["protocol"],
        "event_type": "intrusion-detection",
        "alert_message": data["message"],
        "severity": "high" if int(data["priority"]) == 1 else "medium"
    }

def normalize_ids_log(input_file, output_file):
    normalized_logs = []
    with open(input_file) as f:
        for line in f:
            parsed = parse_ids_line(line.strip())
            if parsed:
                normalized_logs.append(parsed)
    with open(output_file, 'w') as out:
        for entry in normalized_logs:
            out.write(json.dumps(entry) + '\n')

if __name__ == "__main__":
    normalize_ids_log("raw_logs/ids.log", "normalized_logs/ids_normalized.json")
