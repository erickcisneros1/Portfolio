# AI SOC Analyst

An intelligent, AI-powered Security Operations Center (SOC) analyst tool that leverages OpenAI's API to perform automated threat hunting across Microsoft Defender for Endpoint (MDE), Azure Active Directory, and Azure resource logs.

## 🎯 Overview

This tool acts as an agentic AI copilot for SOC analysts, intelligently selecting relevant log sources, querying Azure Log Analytics Workspace, and analyzing results to identify potential security threats. It maps findings to MITRE ATT&CK framework and provides actionable recommendations.

## ✨ Features

- **Intelligent Log Query Selection**: Uses OpenAI function calling to automatically determine which log tables and fields to query based on natural language requests
- **Multi-Source Threat Hunting**: Supports analysis across multiple log sources:
  - Microsoft Defender for Endpoint (DeviceProcessEvents, DeviceNetworkEvents, DeviceLogonEvents, DeviceFileEvents, DeviceRegistryEvents)
  - Azure Active Directory (SigninLogs, AuditLogs)
  - Azure Activity Logs
  - Azure Network Security Group (NSG) Flow Logs
- **MITRE ATT&CK Mapping**: Automatically maps detected threats to MITRE ATT&CK tactics, techniques, and sub-techniques
- **Cost Management**: Intelligent model selection based on token usage, rate limits, and cost estimation
- **Guardrails**: Validates tables, fields, and models to prevent unauthorized queries
- **Structured Output**: Returns findings in structured JSON format with confidence levels, IOCs, and recommendations
- **Threat Logging**: Automatically logs all findings to `_threats.jsonl` for audit and analysis

## 🎬 Demo

This is a demo of the AI SOC Analyst tool.

[![AI SOC Analyst Demo](https://img.youtube.com/vi/ywIGodCko7c/0.jpg)](https://www.youtube.com/watch?v=ywIGodCko7c)

*[Watch the demo on YouTube](https://www.youtube.com/watch?v=ywIGodCko7c)*

## 🏗️ Architecture

The project consists of several modular components:

- **`_main.py`**: Main entry point that orchestrates the threat hunting workflow
- **`EXECUTOR.py`**: Handles OpenAI API calls, log query execution, and threat hunting analysis
- **`PROMPT_MANAGEMENT.py`**: Manages system prompts, tool definitions, and threat hunting instructions
- **`MODEL_MANAGEMENT.py`**: Handles model selection, token counting, cost estimation, and rate limit management
- **`GUARDRAILS.py`**: Validates allowed tables, fields, and models
- **`UTILITIES.py`**: Provides helper functions for query context sanitization, display formatting, and threat visualization

## 📋 Prerequisites

- Python 3.8+
- Azure subscription with:
  - Log Analytics Workspace
  - Microsoft Defender for Endpoint (if querying MDE tables)
  - Azure AD logs (if querying SigninLogs/AuditLogs)
- OpenAI API key with access to GPT models
- Azure CLI configured (`az login`)

## ⚙️ Configuration

### Model Selection

Edit `MODEL_MANAGEMENT.py` to configure:
- `DEFAULT_MODEL`: Default model to use (e.g., "gpt-4.1-nano")
- `CURRENT_TIER`: Your OpenAI API tier ("free", "1", "2", "3", "4", "5")
- `WARNING_RATIO`: Threshold for warnings (default: 0.80 = 80%)

### Allowed Tables and Fields

Edit `GUARDRAILS.py` to modify:
- `ALLOWED_TABLES`: Dictionary of allowed tables and their permitted fields
- `ALLOWED_MODELS`: Dictionary of allowed models with their specifications

## 📖 Usage

Run the main script:
```bash
python _main.py
```

The tool will prompt you for a threat hunting request. Examples:

- "Something is messed up in our AAD/Entra ID for the last 2 weeks or so, particularly about user arisa"
- "Show suspicious PowerShell activity on host WS-123 in the last day"
- "Any failed sign-ins for alice@contoso.com over the past 6 hours?"
- "Were NSG rules blocking outbound 4444 from VM web-01 this weekend?"

### Workflow

1. **Query Selection**: The AI analyzes your request and selects appropriate log tables, fields, and time ranges
2. **Validation**: Guardrails validate the selected tables, fields, and model
3. **Query Execution**: KQL queries are executed against Azure Log Analytics Workspace
4. **Threat Analysis**: The AI analyzes the returned logs for suspicious activity
5. **Results Display**: Findings are displayed with MITRE ATT&CK mapping, IOCs, and recommendations
6. **Threat Logging**: All findings are automatically saved to `_threats.jsonl`

## 📊 Supported Log Sources

### Microsoft Defender for Endpoint
- **DeviceProcessEvents**: Process creation and command-line execution
- **DeviceNetworkEvents**: Network connections and events
- **DeviceLogonEvents**: Authentication and logon activity
- **DeviceFileEvents**: File system operations
- **DeviceRegistryEvents**: Registry modifications
- **AlertInfo**: Alert metadata
- **AlertEvidence**: Alert-related artifacts

### Azure Active Directory
- **SigninLogs**: User sign-in events, authentication results, and risk indicators
- **AuditLogs**: Directory and identity changes

### Azure Resources
- **AzureActivity**: Control plane operations (resource changes, role assignments)
- **AzureNetworkAnalytics_CL**: NSG flow logs via Azure Traffic Analytics

## 🔒 Security Considerations

- **API Keys**: Never commit `_keys.py` to version control. Add it to `.gitignore`
- **Field Validation**: Only pre-approved fields can be queried to prevent data exfiltration
- **Table Validation**: Only whitelisted tables can be accessed
- **Model Validation**: Only approved models can be used
- **PII Handling**: The tool includes instructions to minimize PII exposure in outputs

## 📁 Project Structure

```
AI_SOC_Analyst/
├── _main.py                 # Main entry point
├── EXECUTOR.py              # API calls and query execution
├── PROMPT_MANAGEMENT.py     # Prompt and tool definitions
├── MODEL_MANAGEMENT.py      # Model selection and cost management
├── GUARDRAILS.py            # Validation rules
├── UTILITIES.py             # Helper functions
├── _keys.py                 # API keys and configuration (DO NOT COMMIT)
├── _threats.jsonl           # Logged threat findings
└── README.md                # This file
```

## 🎨 Output Format

Findings are returned in structured JSON format:

```json
{
  "findings": [
    {
      "title": "Brief title describing the suspicious activity",
      "description": "Detailed explanation of why this activity is suspicious",
      "mitre": {
        "tactic": "e.g., Execution",
        "technique": "e.g., T1059",
        "sub_technique": "e.g., T1059.001",
        "id": "e.g., T1059, T1059.001",
        "description": "Description of the MITRE technique/sub-technique"
      },
      "log_lines": ["Relevant log lines"],
      "confidence": "Low | Medium | High",
      "recommendations": ["pivot", "create incident", "monitor", "ignore"],
      "indicators_of_compromise": ["IOCs found in logs"],
      "tags": ["privilege escalation", "persistence", "data exfiltration"],
      "notes": "Optional analyst notes"
    }
  ]
}
```

## 🛠️ Troubleshooting

### Rate Limit Errors
- The tool will automatically warn if queries exceed rate limits
- Consider switching to a model with higher rate limits
- Reduce the time range or number of fields queried

### No Results Returned
- Verify your Azure Log Analytics Workspace ID is correct
- Ensure you have proper permissions to query the workspace
- Check that the time range contains data
- Verify the device/user names are correct

### Authentication Errors
- Run `az login` to authenticate with Azure
- Verify your OpenAI API key is valid
- Check that your Azure credentials have access to the Log Analytics Workspace

## 📝 License

This project is provided as-is for security research and SOC operations.

## 🤝 Contributing

This was a personal project through an internship I am part of, made for personal use and development. Not looking to change or add to it in the near future.

## ⚠️ Disclaimer

This tool is designed for authorized security operations only. Ensure you have proper authorization before querying log data. The authors are not responsible for misuse of this tool.

