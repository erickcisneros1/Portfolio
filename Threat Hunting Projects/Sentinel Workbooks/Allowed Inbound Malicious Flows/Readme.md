# Azure Log Analytics: Malicious Network Flow Geolocation & Visualization

<p align="center">
  <img src="https://img.shields.io/badge/Azure-Log%20Analytics-0072C6?style=for-the-badge&logo=azure-pipelines" alt="Azure Log Analytics">
  <img src="https://img.shields.io/badge/KQL-Query%20Language-blueviolet?style=for-the-badge" alt="KQL">
  <img src="https://img.shields.io/badge/Cyber%20Security-Threat%20Intel-red?style=for-the-badge" alt="Cyber Security">
  <img src="https://img.shields.io/badge/Data%20Visualization-Maps-green?style=for-the-badge" alt="Data Visualization">
</p>

---

## 📜 Overview

This project demonstrates the use of Azure Log Analytics and Kusto Query Language (KQL) to identify, geolocate, and visualize malicious network traffic on a world map. It serves as a practical example of transforming raw security logs from Azure Network Analytics into actionable threat intelligence, suitable for a security operations portfolio. The goal is to provide a clear visual representation of where potential network threats are originating from, aiding in security monitoring and incident response.

---

## ⚙️ How It Works: The KQL Query

The core analysis is performed using a Kusto Query Language (KQL) query within an Azure Log Analytics workspace. The query processes network flow logs, enriches them with geolocation data, and prepares them for visualization.

**KQL Query Breakdown:**

```kql
// 1. Load the Geolocation IP Database from a Watchlist
let GeoIPDB_FULL = _GetWatchlist("geoip");

// 2. Define and Filter Malicious Network Flows
let MaliciousFlows = AzureNetworkAnalytics_CL
| where FlowType_s == "MaliciousFlow"
// || where SrcIP_s == "10.0.0.5" // Example of further filtering (commented out)
| order by TimeGenerated desc
| project TimeGenerated, FlowType = FlowType_s, IpAddress = SrcIP_s, DestinationIpAddress = DestIP_s, DestinationPort = DestPort_d, Protocol = L7Protocol_s, NSGRuleMatched = NSGRules_s;

// 3. Perform Geolocation Lookup and Project Final Data
MaliciousFlows
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network) // 'network' is the IP column in the watchlist
| project TimeGenerated, FlowType, IpAddress, DestinationIpAddress, DestinationPort, Protocol, NSGRuleMatched, latitude, longitude, city = cityname, country = countryname, friendly_location = strcat(cityname, " (", countryname, ")")
```

**Explanation of Query Steps:**

1.  **Load Geolocation Watchlist (`GeoIPDB_FULL`)**:
    *   `_GetWatchlist("geoip")`: Retrieves a pre-configured watchlist named "geoip". This watchlist is assumed to contain IP address ranges mapped to their corresponding geographic details (city, country, latitude, longitude).

2.  **Identify Malicious Flows (`MaliciousFlows`)**:
    *   `AzureNetworkAnalytics_CL`: Targets the table storing network flow logs (likely a custom log table).
    *   `where FlowType_s == "MaliciousFlow"`: Filters these logs to isolate entries specifically flagged as "MaliciousFlow".
    *   `order by TimeGenerated desc`: Sorts the identified malicious flows, showing the most recent ones first.
    *   `project ...`: Selects and renames relevant columns (e.g., `SrcIP_s` to `IpAddress`) for easier use in subsequent steps.

3.  **Enrich and Finalize Data**:
    *   `evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)`: This is the key enrichment step. It uses the `ipv4_lookup` operator to correlate the `IpAddress` from `MaliciousFlows` with the IP ranges in the `GeoIPDB_FULL` watchlist. The `network` parameter specifies the column in the watchlist containing the IP/CIDR data. Successful lookups append geographic columns (latitude, longitude, cityname, countryname) to the flow data.
    *   `project ...`: Selects the final set of columns for output, including the newly acquired `latitude`, `longitude`, and a concatenated `friendly_location` string (e.g., "Irwin (United States)").

---

## 🗺️ Visualization

The output of the KQL query, now enriched with geographic coordinates, is used to generate a map visualization within Azure Log Analytics or a connected dashboard (e.g., Azure Workbooks, Power BI).

![Image](https://github.com/user-attachments/assets/8457bffb-6ced-49d7-be1e-7c226f5dd413)

*   **Geographic Markers:** Points on the map (circles in the example image) represent the source locations of malicious traffic.
*   **Activity Volume:** The size of each marker typically correlates with the count of malicious flows from that location. Larger circles indicate higher activity (e.g., the 1.37k events from Irwin, United States, result in a larger marker than the 236 events from Muncie, United States).
*   **Color Coding (Potential):** Colors (green, yellow, red) can be used to denote different severity levels or ranges of activity, as seen with the prominent red circle over Africa in the example.
*   **Tabular Summary:** A summary table or list often accompanies the map, showing top locations by traffic volume.
*   **Data Scope:** The query and visualization are typically scoped to a specific time range (e.g., "Last 30 days"). The note "Results were limited to the first 100 rows" suggests that for performance or clarity, the visualization might display a subset of the total data if many distinct locations are found.

---

## 🛠️ Technologies Used

*   **Azure Log Analytics:** Core platform for log data aggregation, storage, and KQL-based querying.
*   **Kusto Query Language (KQL):** The language used for data exploration and analysis.
*   **Azure Watchlists:** (Often managed via Azure Sentinel) Used to store and reference the IP geolocation data for enrichment.
*   **Azure Network Analytics:** The service providing the source `AzureNetworkAnalytics_CL` logs.

---

## 🌟 Portfolio Value

This project effectively showcases:
*   **KQL Proficiency:** Demonstrates ability to write complex queries for filtering, joining (via lookup), and transforming data.
*   **Security Data Analysis:** Highlights skills in interpreting and enriching security logs to derive meaningful insights.
*   **Data Enrichment:** Shows understanding of how to combine different datasets (flow logs + geolocation data) to add context.
*   **Visualization Acumen:** Illustrates the ability to present security data in an intuitive, visual format for quick threat assessment.
*   **Azure Ecosystem Knowledge:** Reflects familiarity with Azure services relevant to security operations and data analytics.

---

## 🚀 Potential Enhancements

*   **Automated Alerting:** Configure Azure Monitor alerts or Sentinel analytics rules based on thresholds (e.g., new high-volume malicious IP locations, specific countries).
*   **Trend Analysis:** Modify the KQL to perform time-series analysis, identifying trends or spikes in malicious activity from certain regions.
*   **Destination Geolocation:** Extend the enrichment to also geolocate destination IP addresses for a more complete traffic path view.
*   **Dynamic Threat Intelligence:** Integrate with live threat intelligence feeds for more up-to-date IP reputation data, rather than relying solely on a static watchlist.
*   **SOAR Integration:** Trigger Azure Logic Apps or Sentinel Playbooks for automated response actions (e.g., blocking IPs at the firewall, creating investigation tickets).
