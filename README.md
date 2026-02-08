# 🚀 Cybersecurity Portfolio

Welcome to my cybersecurity portfolio — a curated collection of tools, scripts, and investigations focused on **security operations**, **AI-assisted threat hunting**, and **compliance automation**.

This repository showcases hands-on projects that reflect real SOC workflows, enterprise security controls, and modern detection techniques.

---

## 📦 Projects

---

### 🤖 AI SOC Analyst (Primary Project)

**What it is:**  
An AI-powered SOC analyst tool that leverages the OpenAI API to assist with **threat hunting, investigation, and log analysis** across Microsoft security platforms.

**Purpose:**  
Designed to reduce analyst workload by automating investigative reasoning, intelligently selecting the right data sources, and mapping findings to **MITRE ATT&CK** for faster, higher-confidence decisions.

**Key Capabilities:**
- **Intelligent query selection** — Translates natural language investigations into the correct log tables and optimized KQL queries
- **Multi-source threat hunting** — Correlates data across:
  - Microsoft Defender for Endpoint (process, network, logon, file, registry)
  - Azure AD SignInLogs & AuditLogs
  - Azure Activity Logs
  - NSG Flow Logs
- **MITRE ATT&CK mapping** — Automatically maps findings to tactics, techniques, and sub-techniques
- **Built-in guardrails** — Enforces validated tables, fields, and models with structured JSON output and threat logging to reduce hallucinations and analyst error
- **Actionable results** — Produces investigation summaries with clear security recommendations

**Tech Stack:**
- Python
- OpenAI API
- Microsoft Defender for Endpoint
- Azure / Azure AD Logs

**Use Case:**  
SOC analyst augmentation, threat hunting acceleration, and detection engineering support.

---

### 🔍 Threat Hunting Scenarios

**What it is:**  
A collection of structured threat hunting investigations simulating real-world attacker behavior in enterprise Windows environments.

**Purpose:**  
To demonstrate how to identify malicious activity using logs, telemetry, and investigative logic — mirroring real SOC and DFIR workflows.

**What’s Included:**
- Investigation narratives and threat context
- Step-by-step KQL queries
- Screenshots and analyst reasoning
- Detection and response recommendations

**Tech Used:**
- KQL
- Microsoft Defender for Endpoint
- Azure Sentinel / Log Analytics

**Use Case:**  
SOC training, interview walkthroughs, and threat detection practice.

---

### 🛠️ STIG Compliance PowerShell Scripts

**What it is:**  
A collection of PowerShell scripts that automate **DISA STIG** security hardening for Windows systems.

**Purpose:**  
To simplify and standardize compliance enforcement while reducing manual configuration errors.

**Key Features:**
- Individual scripts mapped to specific STIG IDs
- Registry and policy enforcement logic
- Clear, readable remediation actions
- Designed for repeatable enterprise use

**Tech Used:**
- PowerShell
- Windows Registry
- Windows Security Policies

**Use Case:**  
Compliance automation, security baselining, and system hardening.

---

## 📁 Repository Structure

```

/
├── AI SOC Analyst
│   └── Source code & configurations
├── Threat Hunting Projects
│   └── Investigation scenarios & analysis
├── STIGs
│   └── PowerShell STIG automation scripts
├── README.md

```
---

## 🧠 Skills Demonstrated

- SOC operations & threat hunting
- AI-assisted security automation
- KQL querying and log analysis
- Windows hardening & STIG compliance
- Detection engineering mindset
- Clear security documentation

---

⚡ *Always learning. Always hunting.*

