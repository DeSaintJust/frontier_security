# Example integration point in session management
def handle_user_request(user_request, session):
    # 1. Let the request be processed initially to gather tool call data.
    response = ai_model.process(user_request)

    # 2. Enrich session data and run detection.
    session.add_interaction(user_request, response)
    detection_result = RolePlayBypassDetector.analyze_session(session.get_data())

    # 3. Act based on risk.
    if detection_result['risk_score'] > CONFIG.threshold:
        security_ops.trigger_alert(detection_result)
        session.terminate(reason="Suspicious activity consistent with AI misuse.")
        # Optionally: initiate incident response, ban account, notify authorities.
        log_forensic_data(session, detection_result)
        return "Your request has been blocked due to a security policy violation."

    return response