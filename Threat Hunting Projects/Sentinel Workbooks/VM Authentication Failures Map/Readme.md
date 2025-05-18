# Azure AD Failed Sign-in Attempts: Geolocation Analysis

<p align="center">
  <img src="https://img.shields.io/badge/Azure%20AD-Signin%20Logs-0072C6?style=for-the-badge&logo=azure-active-directory" alt="Azure AD Signin Logs">
  <img src="https://img.shields.io/badge/KQL-Security%20Query-blueviolet?style=for-the-badge" alt="KQL">
  <img src="https://img.shields.io/badge/Cyber%20Security-Threat%20Detection-red?style=for-the-badge" alt="Cyber Security">
  <img src="https://img.shields.io/badge/Geolocation-Failed%20Logins-orange?style=for-the-badge" alt="Geolocation">
</p>

---

## 📜 Overview

This project focuses on analyzing **Azure Active Directory (Azure AD) Sign-in Logs** to identify and visualize the geographic locations of **failed login attempts**. By querying these logs using Kusto Query Language (KQL) in Azure Log Analytics, we can extract crucial information about unsuccessful sign-ins, including the user identity, the location (latitude, longitude, city, country) derived from the source IP address, and the count of failed attempts.

Visualizing this data on a world map helps security analysts quickly spot patterns, such as concentrated failed login attempts from specific regions, which could indicate targeted attacks (e.g., brute-force, password spray) or compromised credentials being tested from unusual locations.

---

## ⚙️ How It Works: The KQL Query

The core of this analysis is a KQL query that processes the `SigninLogs` table, which natively contains rich location information.

**KQL Query:**

```kql
SigninLogs
| where ResultType != 0 // Filter for failed sign-ins (ResultType 0 typically indicates success)
| summarize LoginCount = count() by Identity, // Count failed attempts per identity and location
    Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"]),
    Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]),
    City = tostring(LocationDetails["city"]),
    Country = tostring(LocationDetails["countryOrRegion"])
| project Identity, Latitude, Longitude, City, Country, LoginCount,
    friendly_label = strcat(Identity, " - ", City, ", ", Country)
```

**Explanation of Query Components:**

1.  **`SigninLogs`**
    *   Specifies the `SigninLogs` table in Azure Log Analytics as the data source. This table records all sign-in attempts to Azure AD.

2.  **`| where ResultType != 0`**
    *   Filters the logs to include only **failed** sign-in attempts. In Azure AD `SigninLogs`, a `ResultType` of `0` usually signifies a successful login. Any non-zero value indicates a failure, with different codes representing various reasons (e.g., invalid password, user not found, MFA challenge failed).

3.  **`| summarize LoginCount = count() by Identity, Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"]), Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]), City = tostring(LocationDetails["city"]), Country = tostring(LocationDetails["countryOrRegion"])`**
    *   This is the aggregation step.
    *   `LoginCount = count()`: Counts the number of failed sign-in events.
    *   `by Identity, ...`: Groups these counts by the `Identity` (the user attempting to sign in) and their location details.
    *   `Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"])`: Extracts the latitude from the nested `LocationDetails` field. The `LocationDetails` field is a dynamic object, and we access its properties using bracket notation. `tostring()` ensures the data type is suitable for the map.
    *   Similarly, `Longitude`, `City`, and `Country` are extracted from `LocationDetails`.

4.  **`| project Identity, Latitude, Longitude, City, Country, LoginCount, friendly_label = strcat(Identity, " - ", City, ", ", Country)`**
    *   Selects the columns needed for the final output and visualization.
    *   `friendly_label = strcat(Identity, " - ", City, ", ", Country)`: Creates a user-friendly label for map tooltips or list views, combining the user's identity with their city and country of the failed login attempt.

---

## 🗺️ Visualization Insights

The KQL query output, rich with geographic coordinates and login counts, is then plotted on a map:

![Image](https://github.com/user-attachments/assets/7729081a-96d1-48f6-b485-46381072e8e1)

*   **Failed Login Hotspots:** Each marker (circle) on the map represents a location from which failed Azure AD sign-ins have occurred. The example map shows a significant concentration of failed attempts originating from a location in Africa (large red circle with 2.01k attempts by identity "47c9a4cd-05f1-466b-9c2..."), indicating a high volume of potentially malicious activity from that single point/identity. Other green markers are spread across North America, Europe, and Australia, representing lower volumes of failed logins from those distinct locations.
*   **Volume Indication:** The size and color of the markers are key indicators:
    *   **Size:** Larger circles generally correspond to a higher `LoginCount`.
    *   **Color:** Colors (e.g., green for lower counts, red for very high counts) are used to quickly differentiate the severity or volume of failed attempts.
*   **Summary Data:** A list below the map typically shows the top identities/locations with the highest number of failed logins. "Other 5.39k" aggregates numerous identities with fewer failed attempts.

---

## 🛠️ Technologies Used

*   **Azure Active Directory (Azure AD):** The identity and access management service providing the `SigninLogs`.
*   **Azure Log Analytics:** The platform for storing, querying, and analyzing log data, including Azure AD logs.
*   **Kusto Query Language (KQL):** The powerful query language used to interact with data in Log Analytics.
*   **Built-in Geolocation Data:** `SigninLogs` natively include `LocationDetails`, which often contains IP-derived geolocation, simplifying the enrichment process compared to logs requiring external lookups.

---

## 🌟 Portfolio Value

This project demonstrates:
*   **Identity Security Monitoring:** Analyzing Azure AD sign-in patterns to detect potential threats against user accounts.
*   **Threat Intelligence Application:** Identifying sources of high-volume failed logins, which can be indicative of brute-force or password spraying attacks.
*   **KQL for Data Extraction & Aggregation:** Skillfully using KQL to parse dynamic fields (`LocationDetails`) and aggregate data for meaningful insights.
*   **Effective Security Visualization:** Presenting complex sign-in data in an intuitive map format to highlight geographic risk areas.
*   **Understanding of Azure AD Log Schema:** Familiarity with the structure and meaning of fields within `SigninLogs`.

---

## 🚀 Potential Enhancements

*   **Alerting on Anomalies:** Create Azure Monitor alerts or Sentinel analytics rules for high-volume failed logins from specific countries, new locations for a user, or impossible travel scenarios.
*   **Filter by Specific Failure Reasons:** Further refine the `where` clause to focus on particular `ResultType` error codes (e.g., `50126` for invalid credentials, `50053` for account locked).
*   **Correlate with User Risk Levels:** Join `SigninLogs` with Azure AD Identity Protection risk data to prioritize investigation of failed logins for already risky users.
*   **Track Successful Logins After Failures:** Investigate if a high number of failed logins from one location is eventually followed by a successful login from a different, legitimate location for the same user (potential credential compromise).
*   **Baseline Normal Behavior:** Establish normal login locations for users and alert on deviations.
