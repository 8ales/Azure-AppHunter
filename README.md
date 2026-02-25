# Azure AppHunter

**Azure AppHunter** is an open-source PowerShell tool built for **security researchers**, **red teamers**, and **defenders** to identify **excessive or dangerous permissions** assigned to **Azure Service Principals**.

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

---

## 🔍 Features

- 📌 **Enumerate Dangerous Microsoft Graph Permissions** on Service Principals  
- 🧠 Detect **privileged role assignments** like Global Administrator or App Administrator  
- 🔐 Discover SPs or Managed Identities with privileged Azure role assignments across **subscription**, **child**, and **inherited** scopes  
- 📱 **Device Code Authentication** for Microsoft Graph and Azure ARM APIs  
- 🧭 Minimal dependencies and easy to integrate into your automation or red teaming workflows

---

## 🧪 Use Cases

- Identify overprivileged enterprise applications during cloud security reviews  
- Map potential escalation paths via SPs assigned sensitive Graph permissions  
- Support purple teaming by highlighting Azure AD misconfigurations  
- Understand third-party apps in hybrid cloud and DevOps environments

---

## 🚀 Getting Started

```powershell
# Clone the repo
git clone https://github.com/YOUR-USERNAME/Azure-AppHunter.git
cd Azure-AppHunter

# Import the module
. .\AzureAppHunter.ps1

# Authenticate with Microsoft Graph (and optionally ARM)
Authenticate -TenantId '<your-tenant-id>' -UseARM

# Authenticate with a Service Principal (Graph + ARM)
Authenticate -TenantId '<your-tenant-id>' -ClientId '<app-id>' -ClientSecret '<app-secret>' -UseARM

# Enumerate Service Principals with dangerous permissions
Enumerate -Type ServicePrincipalsDangerousPermissions

# Enumerate privileged role assignments (e.g., App Admin, Global Admin)
Enumerate -Type PrivilegedRoleAssignments

# Identify SPs or MIs with privileged role assignments and explicit scope classification (Subscription/Child/Inherited)
Enumerate -Type SubscriptionOwnersContributors

# Identify SPs or MIs with dangerous subscription permissions (includes Key Vault secret read/list signals)
Enumerate -Type SubscriptionDangerousPermissions
