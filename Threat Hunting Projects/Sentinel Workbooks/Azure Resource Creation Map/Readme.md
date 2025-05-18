# Azure Resource Creation Activity: Geolocation Audit

<p align="center">
  <img src="https://img.shields.io/badge/Azure-Activity%20Log-0072C6?style=for-the-badge&logo=azure-pipelines" alt="Azure Activity Log">
  <img src="https://img.shields.io/badge/KQL-Audit%20Query-blueviolet?style=for-the-badge" alt="KQL">
  <img src="https://img.shields.io/badge/Security%20Auditing-User%20Activity-red?style=for-the-badge" alt="Security Auditing">
  <img src="https://img.shields.io/badge/Geolocation-IP%20Mapping-green?style=for-the-badge" alt="Geolocation">
</p>

---

## 📜 Overview

This project demonstrates how to audit and visualize Azure resource creation activities by geolocating the source IP addresses of the users or services performing these actions. By querying Azure Activity logs with Kusto Query Language (KQL) and enriching the data with a geolocation watchlist, we can map out where resource creation operations originate. This is valuable for security monitoring, identifying anomalous behavior (e.g., resource creation from unexpected locations), and maintaining compliance.

The primary goal is to identify successful resource "WRITE" operations, attribute them to a caller and their IP address, count these operations, and then plot them on a world map.

---

## ⚙️ How It Works: The KQL Query

The analysis is performed using the following KQL query in Azure Log Analytics, targeting the `AzureActivity` table.

**KQL Query:**

```kql
// Only works for IPv4 Addresses
let GeoIPDB_FULL = _GetWatchlist("geoip");
let AzureActivityRecords = AzureActivity
| where not(Caller matches regex @"^([[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?)$") // Exclude service principals/GUIDs
| where CallerIpAddress matches regex @"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b" // Ensure valid IPv4
| where OperationNameValue endswith "WRITE" and (ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded")
| summarize ResourceCreationCount = count() by Caller, CallerIpAddress;
AzureActivityRecords
| evaluate ipv4_lookup(GeoIPDB_FULL, CallerIpAddress, network)
| project Caller,
    CallerPrefix = split(Caller, "@")[0], // Splits Caller UPN and takes the part before @
    CallerIpAddress,
    ResourceCreationCount,
    Country = countryname,
    Latitude = latitude,
    Longitude = longitude,
    friendly_label = strcat(split(Caller, "@")[0], " - ", cityname, ", ", countryname)
```

**Explanation of Query Components:**

1.  **`let GeoIPDB_FULL = _GetWatchlist("geoip");`**
    *   Loads a watchlist named "geoip". This watchlist is expected to contain IP address ranges and their corresponding geographic information (city, country, latitude, longitude).

2.  **`let AzureActivityRecords = AzureActivity ... ;`**
    *   This block defines a temporary dataset `AzureActivityRecords` by processing the `AzureActivity` log table.
    *   `| where not(Caller matches regex @"^([[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?)$")`: This line attempts to filter out entries where the `Caller` is a service principal or managed identity (which often appear as GUIDs). The goal is to focus on human user activity, though this regex might not catch all non-user identities.
    *   `| where CallerIpAddress matches regex @"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"`: Ensures that the `CallerIpAddress` field contains a valid IPv4 address format, as the `ipv4_lookup` operator is specific to IPv4.
    *   `| where OperationNameValue endswith "WRITE" and (ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded")`: Filters for operations that represent resource creation or modification (typically ending in "WRITE") and were successful.
    *   `| summarize ResourceCreationCount = count() by Caller, CallerIpAddress;`: Counts the number of successful write operations, grouping them by the `Caller` (the identity performing the action) and their `CallerIpAddress`.

3.  **`AzureActivityRecords | evaluate ipv4_lookup(...) | project ...`**
    *   Takes the summarized `AzureActivityRecords`.
    *   `| evaluate ipv4_lookup(GeoIPDB_FULL, CallerIpAddress, network)`: Enriches the records by matching the `CallerIpAddress` against the IP ranges in the `GeoIPDB_FULL` watchlist. The `network` argument likely refers to the column in the watchlist containing the IP/CIDR information. This step adds `latitude`, `longitude`, `cityname`, and `countryname` to the dataset.
    *   `| project ...`: Selects and formats the final columns for output:
        *   `Caller`: The original identity.
        *   `CallerPrefix = split(Caller, "@")[0]`: Extracts the username part from a User Principal Name (UPN) for a more concise label.
        *   `CallerIpAddress`: The IP address from which the action was performed.
        *   `ResourceCreationCount`: The total count of resource creations by this caller from this IP.
        *   `Country`, `Latitude`, `Longitude`: Geographic data for map plotting.
        *   `friendly_label = strcat(split(Caller, "@")[0], " - ", cityname, ", ", countryname)`: Creates a descriptive label combining the user prefix, city, and country.

---

## 🗺️ Visualization

The output of this KQL query is then visualized as a map within Azure Log Analytics (or a connected tool like Azure Workbooks).

![Image](https://github.com/user-attachments/assets/29df5dcb-6567-445c-a8f3-e5d10e86a50e)

*   **Geographic Distribution:** Circles on the map represent the geolocated IP addresses from which Azure resources were created. The example map shows significant activity clusters in North America and Europe, with some activity in Asia and Australia.
*   **Activity Volume:** The size and color of the circles typically indicate the `ResourceCreationCount`. Larger and/or more intensely colored circles (e.g., yellow/orange in the example) represent a higher number of resource creation events from that specific user/IP location.
*   **Summary Data:** Below the map, a list often displays the top callers/locations by `ResourceCreationCount`. In the example, "Other 5.1k" aggregates many smaller counts, while individual entries like "4decbfe094c3bb53b3475... 175" show counts for specific (potentially anonymized or service principal) callers.

---

## 🛠️ Technologies Used

*   **Azure Activity Log:** Provides audit trails for all Azure Resource Manager operations.
*   **Azure Log Analytics:** The platform for collecting, querying, and visualizing log data.
*   **Kusto Query Language (KQL):** The query language used to analyze data in Log Analytics.
*   **Azure Watchlists:** (Often managed via Azure Sentinel) Used to store the IP geolocation data for enrichment.

---

## 🌟 Portfolio Value

This project demonstrates:
*   **Cloud Security Auditing:** Ability to query and analyze Azure Activity logs for critical operational insights.
*   **Data Enrichment & Correlation:** Skill in combining log data with external datasets (geolocation) to add valuable context.
*   **KQL Proficiency:** Use of advanced KQL functions like `matches regex`, `summarize`, `evaluate ipv4_lookup`, and string manipulation (`split`, `strcat`).
*   **Threat Detection & Anomaly Identification:** The foundation for identifying unusual resource creation patterns (e.g., activity from unexpected geographic regions).
*   **Data Visualization for Security:** Presenting complex audit data in an easily digestible map format.

---

## 🚀 Potential Enhancements

*   **Alerting:** Configure Azure Monitor alerts for resource creations from unauthorized or suspicious geolocations.
*   **Refine Caller Identification:** Improve the regex or use other fields to better distinguish between user accounts and service principals.
*   **Track Specific Resource Types:** Modify the query to filter or group by the type of resource being created (e.g., Virtual Machines, Storage Accounts).
*   **Historical Trend Analysis:** Analyze changes in resource creation locations and volumes over time.
*   **Integration with Azure Sentinel:** Develop this query into a Sentinel analytics rule to generate incidents for suspicious activities.
