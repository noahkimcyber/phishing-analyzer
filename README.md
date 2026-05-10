\# 🎣 Phishing Email Analyzer



A free, AI-powered web tool that analyzes suspicious emails for phishing threats in seconds.



🔗 \*\*Live App:\*\* \[Click here to use the tool](https://noahkimcyber-phishing-analyzer.streamlit.app)



\---



\## 🔍 What It Does



Paste any suspicious email and the tool will:



\- 🤖 Use AI to analyze the email for phishing indicators

\- 🔗 Scan all URLs against VirusTotal's database of 90+ security vendors

\- 🌐 Check the sender domain reputation

\- 🎯 Generate a phishing risk score from 0-100

\- 📋 Provide a detailed report with verdict, red flags, explanation, and recommended actions



\---



\## 🛠️ How It Works



1\. User pastes a suspicious email into the web interface

2\. All URLs are extracted and scanned with the VirusTotal API

3\. The sender domain is checked against VirusTotal's reputation database

4\. The full email is sent to Groq AI (LLaMA 3.3 70B) for deep analysis

5\. Results are displayed in a clean, easy-to-read dashboard



\---



\## 💻 Tech Stack



| Tool | Purpose |

|---|---|

| Python | Core programming language |

| Streamlit | Web interface and deployment |

| Groq API (LLaMA 3.3 70B) | AI-powered phishing analysis |

| VirusTotal API | URL and domain threat scanning |

| Git \& GitHub | Version control |



\---



\## 🚀 Run It Locally



1\. Clone the repository: 

git clone https://github.com/noahkimcyber/phishing-analyzer.git

cd phishing-analyzer



2\. Install dependencies:

pip install -r requirements.txt



3\. Set your API keys as environment variables:

set GROQ\_API\_KEY=your-groq-key-here

set VIRUSTOTAL\_API\_KEY=your-virustotal-key-here



4\. Run the app:

python -m streamlit run phishing\_analyzer.py



\---



\## 📧 How to Get the Best Results



For the most thorough analysis, use Gmail's \*\*"Show Original"\*\* feature:



1\. Open the suspicious email in Gmail

2\. Click the three dots (⋮) in the top right

3\. Click \*\*"Show original"\*\*

4\. Click \*\*"Copy to clipboard"\*\*

5\. Paste into the analyzer



This reveals hidden headers, real sender IPs, and mail server routing that makes the analysis much more accurate.



\---



\## ⚠️ Disclaimer



This tool is for educational and personal use only. Always report confirmed phishing emails to your email provider and the impersonated organization.



\---



\## 👤 Author



Built by Noah Kim — aspiring cybersecurity professional.



\- GitHub: \[noahkimcyber](https://github.com/noahkimcyber)

