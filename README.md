# 🛡️ STIG Compliance PowerShell Scripts

Welcome to **My STIG Scripts** — a collection of PowerShell scripts designed to automate and enforce security settings based on [DISA STIG](https://public.cyber.mil/stigs/) requirements for Windows systems.

Each script targets a specific STIG ID and includes:

- 📖 A brief synopsis of what the script enforces
- 🔒 The associated STIG ID and security impact
- 💻 PowerShell code to apply the setting
- 📸 Optional screenshots to show before-and-after registry changes

---

## 📁 Folder Structure

Each script is named after the corresponding STIG ID for easy identification.

---

# 🤖 AI SOC Analyst

An **AI-powered SOC analyst tool** that uses OpenAI’s API to automate threat hunting across Microsoft Defender for Endpoint (MDE), Azure AD, and Azure resource logs. It acts as an agentic copilot: it picks relevant log sources, runs KQL against Azure Log Analytics, and analyzes results with MITRE ATT&CK mapping and actionable recommendations.

- 🧠 **Intelligent query selection** — Natural language → automatic choice of log tables and KQL
- 📊 **Multi-source hunting** — MDE (process/network/logon/file/registry), SigninLogs, AuditLogs, Azure Activity, NSG flow logs
- 🎯 **MITRE ATT&CK mapping** — Findings mapped to tactics, techniques, and sub-techniques
- 🔒 **Guardrails** — Validated tables, fields, and models; structured JSON output and threat logging

*[Watch the demo on YouTube](https://www.youtube.com/watch?v=ywIGodCko7c)*

---

# 🔍 Threat Hunting Scenarios

This folder contains real-world **threat hunting investigations** designed to simulate suspicious or malicious activity within a Windows enterprise environment. These scenarios are built to sharpen detection and response skills using tools such as:

- 🛡️ Microsoft Defender for Endpoint (MDE)
- 📊 Kusto Query Language (KQL)
- 💻 Windows 10 VMs (e.g., in Microsoft Azure)

Each scenario includes a detailed narrative, step-by-step hunting queries, screenshots, and analysis.

---

## 👤 Author

**Erick Cisneros Ruballos**  
🔗 [LinkedIn](https://www.linkedin.com/in/erickcr1/)  
💻 [GitHub](https://github.com/erickcisneros1)

---

Stay curious—and keep hunting.
