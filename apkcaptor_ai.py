import google.generativeai as genai
import os
import json
from dotenv import load_dotenv

load_dotenv()
try:
    import streamlit as st
    api_key = st.secrets["GEMINI_API_KEY"]
except:
    api_key = os.getenv("GEMINI_API_KEY")
genai.configure(api_key=api_key)

def generate_ai_analysis(static_results, vt_results, risk_results):
    print("[APKCaptor] Sending findings to Gemini for threat analysis...")

    model = genai.GenerativeModel("gemini-2.5-flash")

    prompt = f"""
You are a senior mobile malware analyst at a bank's cybersecurity team.
Analyze the following APK scan results and provide a threat assessment.

=== STATIC ANALYSIS FINDINGS ===
Package: {static_results['package_name']}
App Name: {static_results['app_name']}
Dangerous Permissions: {json.dumps(static_results['dangerous_permissions'], indent=2)}
Suspicious Code Patterns Found: {json.dumps(static_results['suspicious_strings'], indent=2)}
Background Services: {static_results['services_count']}
Broadcast Receivers: {static_results['receivers_count']}

=== VIRUSTOTAL RESULTS ===
SHA256: {vt_results['hash']}
Flagged by {vt_results['malicious']} out of {vt_results['total_engines']} antivirus engines

=== CALCULATED RISK SCORE ===
Score: {risk_results['score']}/100
Severity: {risk_results['severity']}

Respond in this exact JSON format with no extra text:
{{  "threat_summary": "2-3 sentence plain English summary of what this app likely does",
  "malware_type": "e.g. Banking Trojan / Spyware / Adware / Likely Clean",
  "attack_techniques": ["list", "of", "suspected", "techniques"],
  "targeted_data": ["what data this app likely tries to steal"],
  "confidence": "High / Medium / Low",
  "recommended_actions": ["list", "of", "specific", "actions", "for", "the", "bank"],
  "indicators_of_compromise": ["specific", "suspicious", "findings"]
}}
"""

    response = model.generate_content(prompt)
    raw = response.text
    clean = raw.replace("```json", "").replace("```", "").strip()

    print("[APKCaptor] Threat analysis received. Parsing results...")
    return json.loads(clean)