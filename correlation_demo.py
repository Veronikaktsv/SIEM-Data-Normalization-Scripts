import json

def load_logs(file_path):
    logs = []
    with open(file_path) as f:
        for line in f:
            logs.append(json.loads(line))
    return logs

def correlate_events(fw_logs, ids_logs, endpoint_logs):
    correlated = []
    # Simple correlation: match events with same src_ip and dst_ip or user login
    for fw_event in fw_logs:
        for ids_event in ids_logs:
            if fw_event['src_ip'] == ids_event['src_ip'] and fw_event['dst_ip'] == ids_event['dst_ip']:
                for ep_event in endpoint_logs:
                    if ep_event.get('src_ip') == fw_event['src_ip']:
                        correlated.append({
                            "firewall_event": fw_event,
                            "ids_event": ids_event,
                            "endpoint_event": ep_event
                        })
    return correlated

if __name__ == "__main__":
    fw_logs = load_logs("normalized_logs/firewall_normalized.json")
    ids_logs = load_logs("normalized_logs/ids_normalized.json")
    ep_logs = load_logs("normalized_logs/endpoint_normalized.json")

    correlated_events = correlate_events(fw_logs, ids_logs, ep_logs)
    print(f"Found {len(correlated_events)} correlated events:")
    for event in correlated_events:
        print(json.dumps(event, indent=2))
