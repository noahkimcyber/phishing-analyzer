import streamlit as st
import requests
import re
import os
from groq import Groq

# API keys
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")

# Configure Groq
client = Groq(api_key=GROQ_API_KEY)

def extract_urls(text):
    pattern = r'https?://[^\s]+'
    return re.findall(pattern, text)

def check_url_virustotal(url):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )
    if response.status_code == 200:
        scan_id = response.json()["data"]["id"]
        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{scan_id}",
            headers=headers
        )
        if result.status_code == 200:
            stats = result.json()["data"]["attributes"]["stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            return malicious, suspicious
    return None, None

def extract_domains(text):
    pattern = r'From:.*?@([\w.-]+)'
    return re.findall(pattern, text)

def check_domain_virustotal(domain):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    result = requests.get(
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers=headers
    )
    if result.status_code == 200:
        stats = result.json()["data"]["attributes"]
        malicious = stats.get("last_analysis_stats", {}).get("malicious", 0)
        suspicious = stats.get("last_analysis_stats", {}).get("suspicious", 0)
        reputation = stats.get("reputation", 0)
        return malicious, suspicious, reputation
    return None, None, None

# Page config
st.set_page_config(page_title="Phishing Analyzer", page_icon="🎣", layout="centered")
st.title("🎣 Phishing Email Analyzer")
st.write("Paste a suspicious email below to analyze it for phishing indicators.")

with st.expander("📧 How to properly copy an email from Gmail for best results"):
    st.markdown("""
    **For deep analysis (recommended):**
    1. Open the suspicious email in Gmail
    2. Click the **three dots (⋮)** in the top right of the email
    3. Click **"Show original"**
    4. A new tab will open with the full raw email
    5. Click **"Copy to clipboard"** at the top of that page
    6. Paste the copied text into the box below

    **Why this method is better:**
    - ✅ Reveals the real sender IP address
    - ✅ Shows actual mail server routing
    - ✅ Exposes hidden headers phishers try to fake
    - ✅ Gives the analyzer much more to work with

    **For basic analysis:**
    Simply select and copy the visible email text and paste it below. Good enough for most cases.
    """)

email_text = st.text_area("Paste email here:", height=250, placeholder="Paste the full email content here...")

if st.button("Analyze Email", type="primary"):
    if email_text.strip() == "":
        st.warning("Please paste an email before analyzing.")
    else:
        # VirusTotal URL scan
        urls = extract_urls(email_text)
        url_results = {}
        if urls:
            with st.spinner("Scanning URLs with VirusTotal..."):
                for url in urls:
                    malicious, suspicious = check_url_virustotal(url)
                    url_results[url] = (malicious, suspicious)

        # VirusTotal domain scan
        domains = extract_domains(email_text)
        domain_results = {}
        if domains:
            with st.spinner("Scanning sender domains with VirusTotal..."):
                for domain in domains:
                    malicious, suspicious, reputation = check_domain_virustotal(domain)
                    domain_results[domain] = (malicious, suspicious, reputation)

        # Groq analysis
        with st.spinner("Analyzing email with AI..."):
            url_summary = ""
            if url_results:
                url_summary = "\n\nVirusTotal URL Scan Results:\n"
                for url, (mal, sus) in url_results.items():
                    url_summary += f"- {url}: {mal} malicious, {sus} suspicious detections\n"

            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in phishing detection."},
                    {"role": "user", "content": f"Analyze this email and give me: 1) VERDICT, 2) CONFIDENCE, 3) RED FLAGS, 4) EXPLANATION, 5) RECOMMENDED ACTION:\n\n{email_text}{url_summary}"}
                ]
            )
            analysis = response.choices[0].message.content

            # Get confidence score
            score_response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert. Respond only with a single integer between 0 and 100 representing the phishing risk score. 0 = definitely safe, 100 = definitely phishing. No other text."},
                    {"role": "user", "content": f"What is the phishing risk score for this email?\n\n{email_text}{url_summary}"}
                ]
            )
            try:
                confidence_score = int(score_response.choices[0].message.content.strip())
            except:
                confidence_score = 50

        # Display confidence meter
        st.subheader("🎯 Phishing Risk Score")
        if confidence_score >= 75:
            st.error(f"🚨 High Risk — {confidence_score}/100")
        elif confidence_score >= 40:
            st.warning(f"⚠️ Medium Risk — {confidence_score}/100")
        else:
            st.success(f"✅ Low Risk — {confidence_score}/100")
        st.progress(confidence_score)

        # Display URL results
        if url_results:
            st.subheader("🔗 URL Scan Results")
            for url, (mal, sus) in url_results.items():
                if mal and mal > 0:
                    st.error(f"🚨 {url} — {mal} malicious detections")
                elif sus and sus > 0:
                    st.warning(f"⚠️ {url} — {sus} suspicious detections")
                else:
                    st.success(f"✅ {url} — No threats detected")

        # Display domain results
        if domain_results:
            st.subheader("🌐 Sender Domain Scan Results")
            for domain, (mal, sus, rep) in domain_results.items():
                if mal and mal > 0:
                    st.error(f"🚨 {domain} — {mal} malicious detections, reputation score: {rep}")
                elif sus and sus > 0:
                    st.warning(f"⚠️ {domain} — {sus} suspicious detections, reputation score: {rep}")
                elif rep and rep < 0:
                    st.warning(f"⚠️ {domain} — Negative reputation score: {rep}")
                else:
                    st.success(f"✅ {domain} — No threats detected, reputation score: {rep}")

        # Display analysis
        st.subheader("🤖 AI Analysis")
        st.markdown(analysis)