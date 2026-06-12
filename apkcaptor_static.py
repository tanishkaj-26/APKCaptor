from androguard.misc import AnalyzeAPK
import re

DANGEROUS_PERMISSIONS = [
    "READ_SMS","SEND_SMS", "RECEIVE_SMS"
    "READ_CONTACTS","RECORD_AUDIO",
    "CAMERA","ACCESS_FINE_LOCATION",
    "SYSTEM_ALERT_WINDOW",
    "BIND_ACCESSIBILITY_SERVICE",
    "READ_CALL_LOG", "PROCESS_OUTGOING_CALLS"
]

SUSPICIOUS_STRINGS = [
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    r'(telegram|t\.me)',
    r'(keylog|overlay|accessibility)',
    r'(AES|DES|RC4|Base64)',
]

def analyze_apk(apk_path):
    print(f"[APKCaptor] Analyzing: {apk_path}")
    a, d, dx = AnalyzeAPK(apk_path)

    package_name = a.get_package()
    app_name = a.get_app_name()
    version = a.get_androidversion_name()

    all_permissions = a.get_permissions()
    dangerous_found = [p for p in all_permissions
                       if any(danger in p for danger in DANGEROUS_PERMISSIONS)]
    
    suspicious_hits = []
    for dex in d:
        for method in dex.get_methods():
            src = str(method.get_name())
            for pattern in SUSPICIOUS_STRINGS:
                matches = re.findall(pattern, src, re.IGNORECASE)
                if matches:
                    suspicious_hits.append({
                        "pattern": pattern,
                        "matches": list(set(matches))[:3]
                    })
    
    activities = a.get_activities()
    services = a.get_services()
    receivers = a.get_receivers()

    return {
        "package_name": package_name,
        "app_name": app_name,
        "version": version,
        "total_permissions": len(all_permissions),
        "all_permissions": all_permissions,
        "dangerous_permissions": dangerous_found,
        "suspicious_strings": suspicious_hits[:10],
        "activities_count": len(activities),
        "services_count": len(services),
        "receivers_count": len(receivers),
    }
