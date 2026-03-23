Overview — 

What the tool does end-to-end

Architecture diagram — Python → JSON → Filebeat → Wazuh Indexer → Dashboard

Prerequisites — Python version, packages, API key setup

Installation — script deployment, directory setup, systemd service config

Configuration reference — every variable and CLI argument in a table

Alert filtering logic — exactly how level threshold + 6-digit custom rules work, with a decision table showing rule 999900 (level 3) is always captured
Deduplication logic — fingerprint formula, run-once vs watch mode behavior

Running the analyzer — all usage examples including watch mode and custom level

Filebeat integration — complete step-by-step setup with exact commands

Wazuh Dashboard setup — index pattern creation and useful search filters

Report format — console output example + full OpenSearch JSON schema

Troubleshooting — every error you encountered during this session with fixes

File reference — all files and their paths

Changelog — V1 → V2 → V3 with what changed in each version
