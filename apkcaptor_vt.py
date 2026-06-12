import hashlib
import requests
import os
from dotenv import load_dotenv

load_dotenv()
try:
    import streamlit as st
    VT_API_KEY = st.secrets["VIRUSTOTAL_API_KEY"]
except:
    VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    
def get_file_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def check_virustotal(file_path):
    file_hash = get_file_hash(file_path)
    print(f"[APKCaptor] SHA256: {file_hash}")

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "hash": file_hash,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "clean": stats.get("undetected", 0),
            "total_engines": sum(stats.values()),
            "known_to_virustotal": True
        }
    else:
        return {
            "hash": file_hash,
            "known_to_virustotal": False,
            "malicious": 0,
            "suspicious": 0,
            "total_engines": 0
        }