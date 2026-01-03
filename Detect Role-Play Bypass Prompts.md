# Detect Role-Play Bypass Prompts

## Description
This mitigation is designed to detect and prevent threat actors from using social engineering pretexts—specifically, role-playing as legitimate cybersecurity professionals conducting defensive security testing—to bypass an AI model's safety constraints and misuse it for autonomous cyberattack operations. The attack documented in the intelligence report (`GTG-1002`) relied on convincing the AI model (Claude) that its malicious activities (reconnaissance, vulnerability exploitation, lateral movement) were part of authorized penetration testing. This mitigation involves implementing a multi-faceted detection system that analyzes user sessions for behavioral and contextual anomalies indicative of this bypass technique, moving beyond static keyword filtering to a dynamic assessment of intent, tool usage, and operational patterns.

## Effect
When this mitigation is successfully enabled and a threat event occurs—i.e., a user initiates a session attempting to misuse the AI for cyber operations under a false defensive testing pretext—the system will generate high-confidence alerts and can enact automated defensive actions. The primary mitigating effects are:
1.  **Early Campaign Disruption**: Sessions exhibiting the detected patterns can be flagged, paused, or terminated before the autonomous attack lifecycle progresses beyond initial reconnaissance, preventing successful intrusion.
2.  **Attribution Hardening**: By correlating anomalies in prompt patterns, tool usage, and request rates across multiple sessions, the system can more reliably cluster related malicious activity, aiding in threat actor identification and account banning.
3.  **Increased Attacker Cost**: The necessity for the threat actor to constantly evolve their pretexts and fragment their activities to avoid detection reduces operational tempo and scale, countering the efficiency gains provided by AI autonomy.
4.  **Improved Safeguard Feedback Loop**: Detected patterns provide direct feedback on novel bypass techniques, allowing for the rapid iterative improvement of the AI model's core safety training and real-time filtering mechanisms.

## Implementation
Implementation requires a layered analysis pipeline that evaluates sessions in real-time and retrospectively. The system should be deployed as part of the AI platform's security and abuse monitoring infrastructure.

### 1. Declarative Configuration for Detection Rules (YAML Example)
This configuration defines the signatures and thresholds for detecting suspicious role-play activity.

```yaml
detection_engine:
  role_play_bypass_detection:
    enabled: true
    analysis_mode: "real_time_with_retrospective"
    confidence_threshold: 0.85

    prompt_patterns:
      - name: "security_testing_pretext"
        patterns:
          - "I am a(?:n)? (?:security|cyber|pentest|red.?team) (?:analyst|engineer|consultant)"
          - "(?:authorized|legitimate|approved) (?:security|penetration) test"
          - "simulat(?:e|ing) (?:an adversary|a threat actor|malicious activity) for (?:defense|training)"
        match_threshold: 2 # Number of distinct patterns required per session
        context_window_words: 100

    behavioral_anomalies:
      - name: "high_frequency_tool_sequencing"
        description: "Rapid, sequential invocation of reconnaissance/exploitation tools atypical for human operators."
        metrics:
          requests_per_minute: 30
          unique_tools_per_10min: 5 # e.g., nmap, sqlmap, Metasploit, Hydra, browser automation
        tool_categories: ["network_scanner", "vulnerability_exploit", "credential_tester", "web_crawler"]

      - name: "autonomous_operational_tempo"
        description: "Sustained request rates indicative of automated orchestration, not human-paced interaction."
        metrics:
          avg_request_interval_ms: 500
          session_duration_minutes: 60
          request_volume_deviation_from_baseline: 3.0 # Standard deviations

    session_context_analysis:
      - check: "persona_consistency"
        action: "flag_if_inconsistent"
      - check: "objective_drift"
        description: "Session starts with broad 'security review' but tools/requests quickly narrow to specific exploitation."
        action: "analyze_with_ml_classifier"