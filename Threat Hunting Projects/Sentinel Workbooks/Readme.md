# Azure Log Analytics & KQL: Security Data Geolocation Projects

<p align="center">
  <img src="https://img.shields.io/badge/Azure-Log%20Analytics-0072C6?style=for-the-badge&logo=azure-pipelines" alt="Azure Log Analytics">
  <img src="https://img.shields.io/badge/KQL-Query%20Language-blueviolet?style=for-the-badge" alt="KQL">
  <img src="https://img.shields.io/badge/Cyber%20Security-Portfolio-red?style=for-the-badge" alt="Cyber Security">
  <img src="https://img.shields.io/badge/Data%20Visualization-Maps-green?style=for-the-badge" alt="Data Visualization">
</p>

---

## 🌍 Overview

This collection showcases several projects utilizing **Azure Log Analytics** and **Kusto Query Language (KQL)** to analyze, geolocate, and visualize various security-related events on world maps. Each project demonstrates practical applications of transforming raw log data into actionable intelligence, highlighting skills in cloud security monitoring, data analysis, and visualization.

These examples are designed to be part of a cybersecurity portfolio, illustrating the power of KQL for threat detection, auditing, and understanding access patterns.

---

## 🗺️ Featured Map Projects

Below is a summary of the individual map-based analysis projects included in this repository. Click on each project title to navigate to its detailed `README.md` for a full explanation, KQL query, and visualization insights.

### 1. [Malicious Network Flow Geolocation](./MaliciousNetworkFlows/README.md)
   *   **Description:** Identifies and maps the geographic origins of network traffic flagged as "MaliciousFlow" in Azure Network Analytics logs. This project uses an IP geolocation watchlist for enrichment.
   *   **Key Focus:** External threat source visualization, network security monitoring.

### 2. [Azure Resource Creation Activity Geolocation](./AzureResourceCreations/README.md)
   *   **Description:** Tracks and maps the locations from which Azure resources are being created. This query analyzes Azure Activity logs and uses an IP geolocation watchlist to pinpoint creation origins.
   *   **Key Focus:** Cloud security auditing, resource governance, identifying anomalous provisioning.

### 3. [Azure AD Failed Sign-in Attempts Geolocation](./FailedAzureADLogins/README.md)
   *   **Description:** Visualizes the geographic sources of failed Azure Active Directory sign-in attempts. This helps in identifying potential brute-force attacks or credential abuse.
   *   **Key Focus:** Identity security, threat detection, account takeover monitoring.

### 4. [Azure AD Successful Sign-in Attempts Geolocation](./SuccessfulAzureADLogins/README.md)
   *   **Description:** Maps the locations of successful Azure Active Directory sign-ins. This is useful for understanding legitimate user access patterns and establishing baselines for anomaly detection.
   *   **Key Focus:** User behavior analytics, access auditing, baseline establishment.

---

## 🛠️ Core Technologies Used Across Projects

*   **Azure Log Analytics:** For log data aggregation, storage, and querying.
*   **Kusto Query Language (KQL):** For data manipulation, analysis, and extraction.
*   **Azure AD SigninLogs & AzureActivity Logs:** Primary data sources for identity and resource management events.
*   **Azure Network Analytics Logs:** Source for network flow data.
*   **Azure Watchlists / Built-in Geolocation:** For IP address enrichment and mapping.
*   **Map Visualizations:** Native Log Analytics map rendering capabilities.

---

Thank you for exploring these projects!
