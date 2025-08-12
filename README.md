# SIEM Data Normalization Scripts

This project provides Python scripts to normalize logs from multiple sources (firewalls, IDS, endpoints) into a unified JSON format compatible with SIEM tools like Splunk or ELK.

## Features

- Normalize Cisco ASA firewall logs
- Normalize Snort IDS alerts
- Normalize Windows endpoint logs (simplified example)
- Demonstrate event correlation using normalized data

## Setup

1. Place your raw logs in `raw_logs/` folder.
2. Create `normalized_logs/` folder for output.
3. Run normalization scripts:

    ```bash
    python normalize_firewall.py
    python normalize_ids.py
    python normalize_endpoint.py
    ```

4. Run correlation demo to see linked events:

    ```bash
    python correlation_demo.py
    ```

## Benefits of Normalization

- Consistent field names across log sources
- Easier event correlation and detection of complex attacks
- Simplified ingestion into SIEM platforms like Splunk or ELK

## Sample Logs Included

- Firewall logs: `raw_logs/firewall.log`
- IDS logs: `raw_logs/ids.log`
- Endpoint logs: `raw_logs/endpoint.log`

## License

This project is licensed under the [MIT License](LICENSE).
