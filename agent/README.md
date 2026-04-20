# Heimdall Remote Agent (Phase 1)

This agent runs on a remote machine, tails a Suricata log file, and sends batches of raw lines back to the Heimdall server.

The server parses and normalizes each line into HCES and tags each event with:

- machine.id
- machine.name
- machine.group (optional)

## Files

- run_agent.py: the runnable Phase 1 agent script
- config.example.json: sample configuration

## Setup

1. Copy config.example.json to config.json.
2. Set values:
   - server_url
   - shared_secret
   - log_path
   - log_type
3. Ensure the server is configured with the same AGENT_SHARED_SECRET.

## Run

python agent/run_agent.py --config agent/config.json

## Authentication headers

Each request includes:

- X-Agent-Id
- X-Agent-Name
- X-Agent-Timestamp
- X-Agent-Nonce
- X-Agent-Signature

Signature format:

- HMAC-SHA256(secret, "<timestamp>.<nonce>.<raw_json_body>")

## Payload

POST /api/agent/events body:

{
  "format": "eve.json",
  "machine_group": "branch-office",
  "events": ["raw line 1", "raw line 2"]
}

## Notes

- If machine_id is not configured, the agent tries /etc/machine-id.
- If not available, the agent generates and persists one in state_file.
- The script tails from the end of file and follows log rotation by inode changes.
