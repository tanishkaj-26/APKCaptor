# apkcaptor_report.py
# APKCaptor - HTML Report Generation Module
from datetime import datetime

def clean(text):
    if text is None:
        return ""
    return str(text).replace("<", "&lt;").replace(">", "&gt;")

def generate_report(static_results, vt_results, risk_results, ai_results, output_path="APKCaptor_Threat_Report.html"):
    print("[APKCaptor] Generating professional threat report...")

    severity = risk_results["severity"]
    colors = {
        "CRITICAL": "#dc3232",
        "HIGH": "#e6781e",
        "MEDIUM": "#c8a000",
        "LOW": "#32a032"
    }
    banner_color = colors.get(severity, "#888888")

    def section(title):
        return f'<h2 style="color:#14145a;border-bottom:2px solid #14145a;padding-bottom:6px;">{title}</h2>'

    def bullet_list(items):
        if not items:
            return "<p>None found.</p>"
        lis = "".join(f"<li>{clean(item)}</li>" for item in items)
        return f"<ul>{lis}</ul>"

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>APKCaptor Threat Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; color: #222; }}
        .header {{ text-align: center; margin-bottom: 20px; }}
        .header h1 {{ color: #14145a; font-size: 28px; margin-bottom: 4px; }}
        .header p {{ color: #888; font-size: 13px; }}
        .banner {{ background: {banner_color}; color: white; padding: 14px 20px; border-radius: 6px; font-size: 20px; font-weight: bold; margin-bottom: 24px; }}
        .card {{ background: #f9f9f9; border: 1px solid #ddd; border-radius: 6px; padding: 16px 20px; margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        td {{ padding: 7px 10px; border-bottom: 1px solid #eee; font-size: 14px; }}
        td:first-child {{ font-weight: bold; color: #555; width: 200px; }}
        ul {{ margin: 6px 0; padding-left: 20px; }}
        li {{ margin-bottom: 6px; font-size: 14px; line-height: 1.5; }}
        .footer {{ text-align: center; color: #aaa; font-size: 11px; margin-top: 40px; }}
    </style>
</head>
<body>

<div class="header">
    <h1>APKCaptor Threat Analysis Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
</div>

<div class="banner">
    RISK SCORE: {risk_results['score']}/100 &nbsp;|&nbsp; {severity}
</div>

<div class="card">
    {section("Application Details")}
    <table>
        <tr><td>App Name</td><td>{clean(static_results['app_name'])}</td></tr>
        <tr><td>Package</td><td>{clean(static_results['package_name'])}</td></tr>
        <tr><td>Version</td><td>{clean(str(static_results['version']))}</td></tr>
        <tr><td>SHA256</td><td style="word-break:break-all;">{clean(vt_results['hash'])}</td></tr>
        <tr><td>VirusTotal</td><td>{vt_results['malicious']} / {vt_results['total_engines']} engines flagged</td></tr>
    </table>
</div>

<div class="card">
    {section("AI Threat Assessment")}
    <p>{clean(ai_results.get('threat_summary', 'N/A'))}</p>
    <table>
        <tr><td>Malware Type</td><td>{clean(ai_results.get('malware_type', 'Unknown'))}</td></tr>
        <tr><td>Confidence</td><td>{clean(ai_results.get('confidence', 'N/A'))}</td></tr>
    </table>
</div>

<div class="card">
    {section("Why This Score?")}
    {bullet_list(risk_results['reasons'])}
</div>

<div class="card">
    {section("Suspected Attack Techniques")}
    {bullet_list(ai_results.get('attack_techniques', []))}
</div>

<div class="card">
    {section("Targeted Data")}
    {bullet_list(ai_results.get('targeted_data', []))}
</div>

<div class="card">
    {section("Recommended Actions for the Bank")}
    {bullet_list(ai_results.get('recommended_actions', []))}
</div>

<div class="card">
    {section("Indicators of Compromise (IOCs)")}
    {bullet_list(ai_results.get('indicators_of_compromise', []))}
</div>

<div class="card">
    {section("Dangerous Permissions Detected")}
    {bullet_list(static_results['dangerous_permissions']) if static_results['dangerous_permissions'] else "<p>No dangerous permissions detected.</p>"}
</div>

<div class="footer">
    This report was generated automatically by APKCaptor. For internal use by authorized cybersecurity and fraud prevention teams only.
</div>

</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[APKCaptor] Report saved: {output_path}")
    return output_path