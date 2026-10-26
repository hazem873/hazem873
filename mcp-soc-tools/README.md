# MCP SOC Tools

A small, local Model Context Protocol (MCP) server that provides read-only security-log triage tools. It is intended as a learning project and a starting point for analyst review.

## What it does

- `analyze_security_log(file_path)`: reads a caller-selected plain-text or JSONL log (up to 5 MiB) and flags a few transparent patterns: failed/successful authentication, privilege changes, possible port scanning, malware alerts, and common web-attack strings.
- `explain_finding(finding_type)`: returns safe context for reviewing a flagged category.
- Reports line numbers, limited excerpts, severity labels, repeated source IPs, and explicit limitations.

## Safety and limitations

- Read-only: does not change the supplied file or system.
- Local-only: does not upload logs, call external APIs, scan networks, or run shell commands.
- Heuristic matches are leads for human review, not proof of compromise.
- Input files are capped at 5 MiB; excerpts are capped at 500 characters; results are capped at 5,000.
- Use only on logs you are authorized to access. Logs can contain personal or sensitive data.

## Requirements

- Python 3.10+
- `uv` (recommended) or `pip`

## Install

```powershell
cd mcp-soc-tools
uv venv
.venv\Scripts\Activate.ps1
uv pip install -e .
```

Or:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e .
```

## Configure in Claude Desktop

Edit the MCP client configuration and add:

```json
{
  "mcpServers": {
    "mcp-soc-tools": {
      "command": "C:\\path\\to\\mcp-soc-tools\\.venv\\Scripts\\mcp-soc-tools.exe",
      "args": []
    }
  }
}
```

If the generated executable is unavailable, use the environment's Python executable and module entry point:

```json
{
  "mcpServers": {
    "mcp-soc-tools": {
      "command": "C:\\path\\to\\mcp-soc-tools\\.venv\\Scripts\\python.exe",
      "args": ["-m", "mcp_soc_tools.server"]
    }
  }
}
```

Restart the MCP client after saving configuration. Exact settings location depends on the client and OS.

## Example input

A JSONL file can contain one event per line:

```json
{"timestamp":"2026-01-01T12:00:00Z","message":"Failed password for invalid user admin","source_ip":"203.0.113.10"}
{"timestamp":"2026-01-01T12:01:00Z","message":"Accepted password for operator","source_ip":"198.51.100.8"}
```

The IPs above are reserved documentation examples, not real hosts.

## Run locally

```powershell
python -m mcp_soc_tools.server
```

The server communicates over stdio using MCP. Do not type into the server process; launch it through an MCP-compatible client.

## Development

```powershell
python -m pip install -e ".[dev]"
python -m pytest
```

## Project status

This is a newly created educational prototype. It has not been used in production or independently audited.

