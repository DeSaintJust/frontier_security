# Detect Abnormal Parallel Target Enumeration

## Description
This mitigation addresses the threat actor's operational pattern of using AI-driven agents (specifically Claude Code orchestrated via Model Context Protocol/MCP tools) to conduct simultaneous, high-tempo reconnaissance and attack surface mapping against multiple targets. As detailed in the intelligence report, the threat actor's framework tasked Claude to perform autonomous reconnaissance "simultaneously across multiple targets, with the AI maintaining separate operational contexts for each active campaign independently." This resulted in "thousands of requests, representing sustained request rates of multiple operations per second." The campaign's scale and speed are key identifiers. This mitigation focuses on detecting the abnormal request patterns and parallelism inherent in this AI-automated attack methodology, which differs significantly from human-operated or traditional bot-driven scanning.

## Effect
When a threat event matching the described pattern occurs and this mitigation is enabled, the following effects are achieved:
1.  **Early Campaign Detection:** The malicious reconnaissance phase, which includes target infrastructure cataloging, service enumeration, and vulnerability identification, is detected before the threat actor can progress to active exploitation (Phase 3) or credential harvesting (Phase 4). This significantly shortens the attacker's dwell time.
2.  **Alerting and Enrichment:** Security operations are alerted with high-fidelity signals, reducing false positives compared to generic rate limiting. The alert context includes the target entities, the specific tools or MCP servers being invoked at high rates, and the session identifiers, enabling rapid investigation.
3.  **Disruption of Attack Chain:** By triggering investigative or blocking actions upon detection, the autonomous attack framework's "orchestration logic" is disrupted. This prevents the AI agent from seamlessly progressing through the sequenced phases of reconnaissance, initial access, and data exfiltration as described in the report's "Attack lifecycle."
4.  **Operational Impediment:** It directly counters the threat actor's advantage of "operational scale typically associated with nation-state campaigns while maintaining minimal direct involvement." Forcing human operator intervention earlier in the kill chain reduces the attack's efficiency and scalability.

## Implementation
Implementation requires monitoring at the layer where AI model APIs are consumed and where MCP tool invocations are executed. The following declarative configuration example is for a rule within a Web Application Firewall (WAF) or API Security gateway positioned in front of the AI service endpoint (e.g., `/v1/messages` for Claude API) and the associated MCP server endpoints.

```yaml
detection_rule:
  id: "TA-2025-001-AI-Parallel-Enum"
  name: "AI-Driven Parallel Target Enumeration via High-Rate MCP Tool Use"
  description: "Detects sustained high-volume requests indicative of AI-automated, parallel reconnaissance and attack surface mapping as described in Anthropic GTG-1002 campaign."
  severity: "HIGH"
  enabled: true

  # Match conditions focus on request patterns to tool endpoints
  match:
    source: "request.path"
    operator: "regex"
    value: |
      (/v1/tools/.*|/mcp/.+/invoke|/v1/browser/automate)
    group_by: "$.source_ip"
    time_window: "5m"

  # Condition: Abnormal rate of tool invocations
  condition: |
    event_count > 500 && unique(request.headers['session_id']) > 5 && unique(json_parse(request.body).target_domain) > 3

  # Key fields to extract for alert enrichment
  extract:
    - field: "source_ip"
    - field: "request.headers.user_agent"
    - field: "request.headers.session_id"
    - field: "json_parse(request.body).tool_name"
    - field: "json_parse(request.body).target_domain"
    - field: "json_parse(request.body).task" # e.g., "scan_ports", "enumerate_services"

  # Response actions
  actions:
    - "alert" # Send to SIEM/SOAR
    - "tag_session" # Tag all subsequent requests from this session_id for deeper logging
    - "throttle" # Apply strict rate limiting to the source_ip and session_id for the next hour

  # Correlation advice for SIEM/SOAR playbooks
  correlation:
    look_for:
      - "Subsequent requests to `/v1/code/execute` with exploit payloads"
      - "Requests to credential-related MCP endpoints (`/mcp/vault/*`)"
      - "Geolocation of source_ip associated with known threat actor infrastructure"