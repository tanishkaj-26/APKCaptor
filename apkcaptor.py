# apkcaptor.py
# APKCaptor - Main Web Interface
import streamlit as st
import tempfile
import os
from apkcaptor_static import analyze_apk
from apkcaptor_vt import check_virustotal
from apkcaptor_scorer import calculate_risk_score
from apkcaptor_ai import generate_ai_analysis
from apkcaptor_report import generate_report

# Page config
st.set_page_config(
    page_title="APKCaptor",
    page_icon="🔍",
    layout="centered"
)

# Header
st.markdown("""
    <div style='text-align:center; padding: 20px 0;'>
        <h1 style='color:#14145a; font-size:42px;'>🔍 APKCaptor</h1>
        <p style='color:#888; font-size:16px;'>AI-Powered Malicious APK Detection for Banking Security Teams</p>
    </div>
""", unsafe_allow_html=True)

st.markdown("---")

# File Upload
uploaded_file = st.file_uploader("Upload a suspicious APK file", type=["apk"])

if uploaded_file:
    st.info(f"File received: **{uploaded_file.name}** ({round(uploaded_file.size / 1024, 1)} KB)")

    if st.button("🚀 Run Analysis", type="primary", use_container_width=True):

        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
            tmp.write(uploaded_file.read())
            tmp_path = tmp.name

        try:
            # Step 1 - Static Analysis
            with st.spinner("🔎 Running static analysis..."):
                static = analyze_apk(tmp_path)
            st.success("✅ Static analysis complete")

            # Step 2 - VirusTotal
            with st.spinner("🌐 Checking VirusTotal..."):
                vt = check_virustotal(tmp_path)
            st.success("✅ VirusTotal check complete")

            # Step 3 - Risk Score
            with st.spinner("📊 Calculating risk score..."):
                score = calculate_risk_score(static, vt)
            st.success("✅ Risk score calculated")

            # Step 4 - AI Analysis
            with st.spinner("🤖 Getting AI threat analysis from Gemini..."):
                ai = generate_ai_analysis(static, vt, score)
            st.success("✅ AI analysis complete")

            # Step 5 - Report
            with st.spinner("📄 Generating report..."):
                report_path = generate_report(static, vt, score, ai)
            st.success("✅ Report generated")

            st.markdown("---")

            # Risk Score Banner
            severity = score["severity"]
            banner_colors = {
                "CRITICAL": "#dc3232",
                "HIGH": "#e6781e",
                "MEDIUM": "#c8a000",
                "LOW": "#32a032"
            }
            color = banner_colors.get(severity, "#888")
            st.markdown(f"""
                <div style='background:{color}; color:white; padding:16px 20px; border-radius:8px; font-size:22px; font-weight:bold; text-align:center; margin-bottom:20px;'>
                    RISK SCORE: {score['score']}/100 &nbsp;|&nbsp; {severity}
                </div>
            """, unsafe_allow_html=True)

            # Metrics Row
            col1, col2, col3 = st.columns(3)
            col1.metric("Dangerous Permissions", len(static["dangerous_permissions"]))
            col2.metric("VT Detections", vt["malicious"])
            col3.metric("Suspicious Patterns", len(static["suspicious_strings"]))

            st.markdown("---")

            # AI Summary
            st.subheader("🤖 AI Threat Assessment")
            st.info(ai.get("threat_summary"))
            col1, col2 = st.columns(2)
            col1.write(f"**Malware Type:** {ai.get('malware_type')}")
            col2.write(f"**Confidence:** {ai.get('confidence')}")

            # Details in expanders
            with st.expander("⚠️ Why This Score?"):
                for r in score["reasons"]:
                    st.write(f"• {r}")

            with st.expander("🎯 Suspected Attack Techniques"):
                for t in ai.get("attack_techniques", []):
                    st.write(f"• {t}")

            with st.expander("🎯 Targeted Data"):
                for t in ai.get("targeted_data", []):
                    st.write(f"• {t}")

            with st.expander("✅ Recommended Actions"):
                for a in ai.get("recommended_actions", []):
                    st.write(f"• {a}")

            with st.expander("🔍 Indicators of Compromise"):
                for i in ai.get("indicators_of_compromise", []):
                    st.write(f"• {i}")

            with st.expander("🔐 Dangerous Permissions Detected"):
                if static["dangerous_permissions"]:
                    for p in static["dangerous_permissions"]:
                        st.write(f"• {p}")
                else:
                    st.write("No dangerous permissions found.")

            st.markdown("---")

            # Download Report
            with open(report_path, "r", encoding="utf-8") as f:
                report_html = f.read()

            st.download_button(
                label="📥 Download Full HTML Report",
                data=report_html,
                file_name="APKCaptor_Threat_Report.html",
                mime="text/html",
                use_container_width=True
            )

        except Exception as e:
            st.error(f"[APKCaptor] Error during analysis: {e}")

        finally:
            os.unlink(tmp_path)

else:
    st.markdown("""
       <div style='text-align:center; padding:60px;'>
            <p style='font-size:18px; font-weight:500; color:#aaa; margin-bottom:20px;'>Upload a suspicious APK file above to begin analysis</p>
            <div style='display:flex; justify-content:center; align-items:center; gap:8px;'>
                <div style='background:#14145a; color:white; padding:8px 14px; border-radius:6px; font-size:12px; font-weight:bold; white-space:nowrap;'>🔎 Scan for Malicious Behavior</div>
                <span style='color:#aaa; font-size:18px;'>→</span>
                <div style='background:#14145a; color:white; padding:8px 14px; border-radius:6px; font-size:12px; font-weight:bold; white-space:nowrap;'>📊 Calculate Risk Score</div>
                <span style='color:#aaa; font-size:18px;'>→</span>
                <div style='background:#14145a; color:white; padding:8px 14px; border-radius:6px; font-size:12px; font-weight:bold; white-space:nowrap;'>📄 Generate Threat Report</div>
            </div>
        </div>
    """, unsafe_allow_html=True)