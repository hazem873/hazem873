from __future__ import annotations

import json
from mcp.server.fastmcp import FastMCP
from .analyzer import analyze_file

mcp = FastMCP("mcp-soc-tools")


@mcp.tool()
def analyze_security_log(file_path: str) -> str:
    """Analyze a user-selected local security log file using read-only heuristics.

    Supported inputs include plain-text logs and newline-delimited JSON. Files are limited to 5 MiB.
    The tool never modifies the file, contacts external services, or treats a finding as confirmed compromise.
    """
    try:
        return json.dumps(analyze_file(file_path), ensure_ascii=False, indent=2)
    except (OSError, ValueError) as exc:
        return json.dumps({"error": str(exc)}, ensure_ascii=False)


@mcp.tool()
def explain_finding(finding_type: str) -> str:
    """Explain the meaning and safe follow-up for a finding category."""
    explanations = {
        "failed_auth": "Check whether failures cluster by account, source, and time. Confirm against identity-provider logs before concluding an attack.",
        "successful_auth": "Verify the account, source address, device, and timing against an authorized-user baseline.",
        "privilege_change": "Review the command, initiating account, approval trail, and surrounding events.",
        "port_scan": "Correlate with firewall and endpoint telemetry; authorized scanners can produce similar events.",
        "malware_alert": "Follow your endpoint protection team's containment and investigation process; do not delete evidence.",
        "web_attack": "Validate against application logs and request context; encoded or benign test strings can match heuristics.",
    }
    return explanations.get(finding_type, "Unknown finding type. Use analyze_security_log to see supported categories.")


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

