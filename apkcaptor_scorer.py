def calculate_risk_score(static_results, vt_results):
    score = 0
    reasons = []

    malicious = vt_results.get("malicious", 0)
    if malicious >= 10:
        score += 40
        reasons.append(f"Flagged by {malicious} antivirus engines on VirusTotal")
    elif malicious >= 5:
        score += 25
        reasons.append(f"Flagged by {malicious} antivirus engines on VirusTotal")
    elif malicious >= 1:
        score += 15
        reasons.append(f"Flagged by {malicious} antivirus engines on VirusTotal")

    dangerous = static_results.get("dangerous_permissions", [])
    perm_score = min(len(dangerous) * 5, 30)
    score += perm_score
    if dangerous:
        reasons.append(f"Requests {len(dangerous)} high-risk permissions: {', '.join([p.split('.')[-1] for p in dangerous[:3]])}")

    hits = static_results.get("suspicious_strings", [])
    string_score = min(len(hits) * 4, 20)
    score += string_score
    if hits:
        reasons.append(f"Found {len(hits)} suspicious code patterns")
    
    if static_results.get("receivers_count", 0) > 5:
        score += 5
        reasons.append("Unusually high number of broadcast receivers")
    if static_results.get("services_count", 0) > 5:
        score += 5
        reasons.append("Unusually high number of background services")

    score = min(score, 100)

    if score >= 75:
        severity = "CRITICAL"
    elif score >= 50:
        severity = "HIGH"
    elif score >= 25:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "score": score,
        "severity": severity,
        "reasons": reasons
    }
