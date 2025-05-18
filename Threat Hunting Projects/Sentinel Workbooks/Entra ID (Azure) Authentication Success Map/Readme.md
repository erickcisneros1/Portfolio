# Azure AD Successful Sign-in Attempts: Geolocation Analysis

<p align="center">
  <img src="https://img.shields.io/badge/Azure%20AD-Successful%20Signins-0072C6?style=for-the-badge&logo=azure-active-directory" alt="Azure AD Signin Logs">
  <img src="https://img.shields.io/badge/KQL-Access%20Audit-blueviolet?style=for-the-badge" alt="KQL">
  <img src="https://img.shields.io/badge/User%20Behavior-Access%20Patterns-1E90FF?style=for-the-badge" alt="User Behavior">
  <img src="https://img.shields.io/badge/Geolocation-Login%20Mapping-green?style=for-the-badge" alt="Geolocation">
</p>

---

## 📜 Overview

This project focuses on analyzing **Azure Active Directory (Azure AD) Sign-in Logs** to identify and visualize the geographic locations of **successful login attempts**. By querying these logs using Kusto Query Language (KQL) in Azure Log Analytics, we can extract details about successful sign-ins, including the user identity and the location (latitude, longitude, city, country) derived from the source IP address.

Visualizing this data on a world map helps in understanding legitimate user access patterns, establishing baselines for normal activity, and can aid in identifying potentially compromised accounts if successful logins occur from highly unusual or impossible travel locations for a given user.

---

## 🖼️ Visuals

**KQL Query Editor View:**
*(This is where you would embed the image of your KQL query for successful sign-ins)*
`[Image of KQL Query for Successful Sign-in Map - as provided in the prompt]`
*Caption: KQL query in Azure Log Analytics for identifying and geolocating successful Azure AD sign-in events.*

**Map Visualization Output:**
*(This is where you would embed the image of your map visualization for successful sign-ins)*
`[Image of Successful Sign-in Activity Map - as provided in the prompt]`
*Caption: World map visualizing the geographic distribution of successful Azure AD sign-ins. Marker size often indicates the volume of logins from specific locations/users. The note "Results were limited to the first 100 rows" suggests the visualization is showing a sample of the most frequent login locations/identities.*

---

## ⚙️ How It Works: The KQL Query

The analysis is driven by a KQL query that processes the `SigninLogs` table, filtering for successful events.

**KQL Query:**

```kql
SigninLogs
| where ResultType == 0 // Filter for successful sign-ins
| summarize LoginCount = count() by Identity, // Count successful attempts per identity and location
    Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"]),
    Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]),
    City = tostring(LocationDetails["city"]),
    Country = tostring(LocationDetails["countryOrRegion"])
| project Identity, Latitude, Longitude, City, Country, LoginCount,
    friendly_label = strcat(Identity, " - ", City, ", ", Country)
```

**Explanation of Query Components:**

1.  **`SigninLogs`**
    *   Specifies the `SigninLogs` table in Azure Log Analytics as the data source.

2.  **`| where ResultType == 0`**
    *   Filters the logs to include only **successful** sign-in attempts. In Azure AD `SigninLogs`, a `ResultType` of `0` signifies a successful login.

3.  **`| summarize LoginCount = count() by Identity, Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"]), Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]), City = tostring(LocationDetails["city"]), Country = tostring(LocationDetails["countryOrRegion"])`**
    *   Aggregates the data.
    *   `LoginCount = count()`: Counts the number of successful sign-in events.
    *   `by Identity, ...`: Groups these counts by the `Identity` (the user signing in) and their location details.
    *   `Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"])`: Extracts the latitude from the nested `LocationDetails` dynamic field.
    *   Similarly, `Longitude`, `City`, and `Country` are extracted from `LocationDetails`.

4.  **`| project Identity, Latitude, Longitude, City, Country, LoginCount, friendly_label = strcat(Identity, " - ", City, ", ", Country)`**
    *   Selects the columns for the final output.
    *   `friendly_label = strcat(Identity, " - ", City, ", ", Country)`: Creates a descriptive label for map tooltips, combining the user's identity with the city and country of the successful login.

---

## 🗺️ Visualization Insights

The KQL query output is visualized on a world map, showing where successful logins are originating:

![Image](https://github.com/user-attachments/assets/b834362b-1c3c-438a-b18c-6f3167b5396a)

*   **Legitimate Access Patterns:** Markers (circles) on the map indicate geographic locations of successful Azure AD sign-ins. The example map shows dominant clusters of successful logins in North America and Europe, with scattered activity in Asia and Australia. This likely reflects the primary operating regions of the organization's users.
*   **Volume Indication:**
    *   **Size:** Larger circles generally correspond to a higher `LoginCount` from that identity/location.
    *   **Color:** Colors (e.g., green, yellow, orange/red for higher concentrations) can help differentiate login volumes. The example shows varying shades and sizes, with the largest concentrations in the US.
*   **Summary Data:** A list below the map shows top identities/locations by successful login count. "Other 17.7k" aggregates many identities with fewer logins. Individual entries (e.g., "64a44581826e58f0eb91a4... 635") show counts for specific identities.
*   **Data Limitation:** The note "Results were limited to the first 100 rows" indicates the map is displaying the top 100 most frequent identity/location combinations for successful logins within the selected time range.

---

## 🛠️ Technologies Used

*   **Azure Active Directory (Azure AD):** Source of the `SigninLogs`.
*   **Azure Log Analytics:** Platform for log data storage, querying, and visualization.
*   **Kusto Query Language (KQL):** Used for data analysis and extraction.
*   **Built-in Geolocation Data:** `SigninLogs` natively provide `LocationDetails` for IP-based geolocation.

---

## 🌟 Portfolio Value

This project demonstrates:
*   **Understanding User Access Behavior:** Analyzing legitimate sign-in patterns to establish a baseline of normal activity.
*   **Auditing and Compliance:** Tracking where and when users are successfully accessing resources.
*   **Foundation for Anomaly Detection:** While this query shows successful logins, the data can be used to identify deviations (e.g., a user successfully logging in from a new, unexpected country).
*   **KQL for Data Parsing:** Efficiently extracting and transforming data from nested JSON-like fields within logs.
*   **Clear Data Presentation:** Visualizing access patterns geographically for intuitive understanding.

---

## 🚀 Potential Enhancements

*   **New Location Detection:** Create alerts for users successfully logging in from a geographic location for the first time or after a long period of inactivity from that location.
*   **Impossible Travel Detection:** Correlate timestamps and locations of consecutive successful logins for the same user to detect physically impossible travel scenarios.
*   **Correlate with Risky Sign-ins:** Even if a sign-in is successful, Azure AD might flag it as "risky." Join this data with `AADRiskyUsers` or risky sign-in properties to highlight successful but potentially compromised sessions.
*   **Application-Specific Login Tracking:** Filter by `AppDisplayName` to see login patterns for specific applications.
*   **Device Information:** Incorporate device information (`DeviceDetail`) to see if logins are coming from known/managed or unknown devices.
