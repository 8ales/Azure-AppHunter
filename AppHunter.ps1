# Global variables for tokens
$global:GraphAccessToken = $null
$global:ARMToken = $null
$global:ToolName = "AzureAppHunter"

# Function to display a banner when the module is imported
function Show-Banner {
    $banner = @'

                                                                       _                    _
  __ _  ____ _   _  _ __   ___                     __ _  _ __   _ __  | |__   _   _  _ __  | |_   ___  _ __
 / _` ||_  /| | | || '__| / _ \                   / _` || '_ \ | '_ \ | '_ \ | | | || '_ \ | __| / _ \| '__|
| (_| | / / | |_| || |   |  __/                  | (_| || |_) || |_) || | | || |_| || | | || |_ |  __/| |
 \__,_|/___| \__,_||_|    \___|                   \__,_|| .__/ | .__/ |_| |_| \__,_||_| |_| \__| \___||_|

  Azure AppHunter v1.1 by Nintendo && @nickvourd && Thomas-Butterfield
'@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host "Welcome to AzureAppHunter!" -ForegroundColor Green
}

# Show banner when module is imported
Show-Banner

# Function to get help on available commands
function Show-Help {
    Write-Host "`nAvailable Commands:" -ForegroundColor Yellow
    Write-Host "1. Authenticate: Authenticates with Microsoft Graph and optionally ARM." -ForegroundColor White
    Write-Host "2. Enumerate: Enumerates Service Principals and identifies dangerous permissions." -ForegroundColor White
}

# Function to authenticate with Microsoft Graph and optionally ARM
<#
.SYNOPSIS
Authenticates with Microsoft Graph and optionally Azure Resource Manager (ARM).

.DESCRIPTION
This function authenticates the user with Microsoft Graph using device code authentication.
Optionally, the user can authenticate with Azure Resource Manager by setting the UseARM flag.

.PARAMETER TenantId
The tenant ID to authenticate with.

.PARAMETER UseARM
A switch that indicates whether to authenticate with Azure Resource Manager (ARM).

.EXAMPLE
Authenticate -TenantId 'your-tenant-id'

.EXAMPLE
Authenticate -TenantId 'your-tenant-id' -UseARM

#>
function Authenticate {
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [Parameter(Mandatory = $false)]
        [switch]$UseARM
    )

    # Authenticate with Microsoft Graph (default)
    Get-MicrosoftGraphToken -TenantId $TenantId

    # Optionally authenticate with ARM if the user provides the flag
    if ($UseARM) {
        Get-ARMToken -TenantId $TenantId
    }
}
# Function to authenticate with Microsoft Graph (default behavior)
# Function to authenticate with Microsoft Graph using device code flow
function Get-MicrosoftGraphToken {
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantId
    )

    $psClientId = "1950a258-227b-4e31-a9cf-717495945fc2"  # PowerShell App Client ID for Microsoft Graph
    $deviceCodeUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"
    $graphScope = "https://graph.microsoft.com/.default"
    $body = @{
        client_id = $psClientId
        scope     = $graphScope
    }

    # Request device code for Microsoft Graph
    try {
        $authResponse = Invoke-RestMethod -UseBasicParsing -Method Post -Uri $deviceCodeUrl -ContentType "application/x-www-form-urlencoded" -Body $body -ErrorAction SilentlyContinue
        Write-Host "Please authenticate by visiting $($authResponse.verification_uri) and entering the code: $($authResponse.user_code)"
    } catch {
        Write-Verbose ($_.Exception.Message)
        throw $_.Exception.Message
    }

    # Get the polling interval and expiration time from the response
    $interval = $authResponse.interval
    $expiresIn = $authResponse.expires_in

    # Set up the token request body for polling
    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $tokenBody = @{
        client_id   = $psClientId
        grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
        device_code = $authResponse.device_code
    }

    $graphTokenResponse = $null
    $totalWaitTime = 0
    $continue = $true
    # Polling loop: keep requesting the token until the user authenticates or the token request expires
    while ($continue -and $totalWaitTime -lt $expiresIn) {
    try {
        # Poll for the token using the baseline logic
        $graphTokenResponse = Invoke-RestMethod -Method Post -Uri $tokenUrl -ContentType "application/x-www-form-urlencoded" -Body $tokenBody -ErrorAction Stop

    } catch {
            # This is normal flow, always returns 40x unless successful
            $details = $_.ErrorDetails.Message | ConvertFrom-Json
            $continue = $details.error -eq "authorization_pending"
            #Write-Output $details.error

            if (!$continue) {
                # Not pending so this is a real error
                #Write-Error $details.error_description
                return
            }
        }

    # Stop polling if the expiration time has been reached
    if ($totalWaitTime -ge $expiresIn) {
        Write-Host "Authentication window has expired. Please try again." -ForegroundColor Red
        $continue = $false
    }
}
}

# Function to enumerate Service Principals and find dangerous permissions
<#
.SYNOPSIS
Enumerates Service Principals for dangerous permissions, Role Assignments for privileged roles, or Subscription Owners & Contributors.

.DESCRIPTION
This function allows enumeration of:
1. Service Principals with dangerous permissions (Find-DangerousServicePrincipals)
2. Role Assignments with privileged roles (Find-PrivilegedRoleAssignments)
3. Subscription Owners & Contributors (Find-SubscriptionOwnersContributors)

.PARAMETER Type
Specify "ServicePrincipalsDangerousPermissions" to enumerate Service Principals with dangerous permissions.
Specify "PrivilegedRoleAssignments" to enumerate Role Assignments with privileged roles.
Specify "SubscriptionOwnersContributors" to enumerate Subscription Owners & Contributors (SPs & MIs Only).

.EXAMPLE
Enumerate -Type ServicePrincipalsDangerousPermissions
Enumerate -Type ServicePrincipalsDangerousPermissions -ExportSP
Enumerate -Type PrivilegedRoleAssignments
Enumerate -Type SubscriptionOwnersContributors
#>
function Enumerate {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("ServicePrincipalsDangerousPermissions", "PrivilegedRoleAssignments", "SubscriptionOwnersContributors")]
        [string]$Type,

        [Parameter(Mandatory = $false)]
        [switch]$ExportSP

    )

    switch ($Type) {
        "ServicePrincipalsDangerousPermissions" {
            Write-Host "[*] Enumerating Service Principals for Dangerous Permissions..." -ForegroundColor Cyan
            Find-DangerousServicePrincipals
        }
        "PrivilegedRoleAssignments" {
            Write-Host "[*] Enumerating Role Assignments for Privileged Roles..." -ForegroundColor Cyan
            Find-PrivilegedRoleAssignments
        }
        "SubscriptionOwnersContributors" {
            Write-Host "[*] Enumerating Subscription Owners & Contributors (SPs & MIs Only)..." -ForegroundColor Cyan
            if (-not $Global:ARMToken) {
                Write-Host "Authentication Required: Please run 'Authenticate -TenantId your-tenant-id -UseARM' before using this enumeration." -ForegroundColor Yellow
                return
            }
            Find-SubscriptionOwnersContributors
        }
        default {
            Write-Host "[-] Invalid option. Please use 'ServicePrincipalsDangerousPermissions', 'PrivilegedRoleAssignments', or 'SubscriptionOwnersContributors'." -ForegroundColor Red
        }
    }
}

function Get-MicrosoftGraphToken {
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantId
    )

    $psClientId = "1950a258-227b-4e31-a9cf-717495945fc2"  # PowerShell App Client ID for Microsoft Graph
    $deviceCodeUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"
    $graphScope = "https://graph.microsoft.com/.default"
    $body = @{
        client_id = $psClientId
        scope     = $graphScope
    }

    # Request device code for Microsoft Graph
    try {
        $deviceCodeResponse = Invoke-RestMethod -Uri $deviceCodeUrl -Method Post -ContentType "application/x-www-form-urlencoded" -Body $body
        Write-Host "Please authenticate by visiting $($deviceCodeResponse.verification_uri) and entering the code: $($deviceCodeResponse.user_code)"
    } catch {
        Write-Error "Failed to initiate device code flow: $($_.Exception.Message)"
        return
    }

    $interval = $deviceCodeResponse.interval
    $expiresIn = $deviceCodeResponse.expires_in
    $totalWaitTime = 0
    $continue = $true
    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $tokenBody = @{
        grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
        client_id   = $psClientId
        device_code = $deviceCodeResponse.device_code
    }

    $graphTokenResponse = $null
    while ($continue -and $totalWaitTime -lt $expiresIn) {
        Write-Host "Waiting for device auth... ($totalWaitTime seconds waited)"
        Start-Sleep -Seconds $interval
        $totalWaitTime += $interval

        try {
            $graphTokenResponse = Invoke-RestMethod -Uri $tokenUrl -Method Post -ContentType "application/x-www-form-urlencoded" -Body $tokenBody
            if ($graphTokenResponse.access_token) {
                $global:GraphAccessToken = $graphTokenResponse.access_token
                Write-Host "✅ Successfully authenticated for Microsoft Graph. GraphAccessToken is now available globally." -ForegroundColor Green
                $continue = $false
                break
            }
        } catch {
            try {
                $details = $_.ErrorDetails.Message | ConvertFrom-Json
                $continue = $details.error -eq "authorization_pending"
                if (!$continue) {
                    Write-Error $details.error_description
                    return
                }
            } catch {
                Write-Error "Unexpected error format: $($_.Exception.Message)"
                return
            }
        }
    }

    if ($totalWaitTime -ge $expiresIn) {
        Write-Host "❌ Authentication window has expired. Please try again." -ForegroundColor Red
    }
}

# Internal function to get optional ARM token (hidden from help)
function Get-ARMToken {
   param (
        [Parameter(Mandatory = $true)]
        [string]$TenantId
    )

    # Define the ARM Device Code URL
    $deviceCodeUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"

    # Set up the request body for device authentication
    $body = @{
        client_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Public Client ID (Microsoft Azure CLI)
        scope     = "https://management.azure.com//.default"
    }

    # Request device code for ARM authentication
    try {
        $authResponse = Invoke-RestMethod -UseBasicParsing -Method Post -Uri $deviceCodeUrl -ContentType "application/x-www-form-urlencoded" -Body $body -ErrorAction Stop
        Write-Host "Please authenticate by visiting $($authResponse.verification_uri) and entering the code: $($authResponse.user_code)" -ForegroundColor Cyan
    } catch {
        Write-Verbose ($_.Exception.Message)
        throw $_.Exception.Message
    }

    # Get the polling interval and expiration time from the response
    $interval = $authResponse.interval
    $expiresIn = $authResponse.expires_in

    # Set up the token request body for polling
    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $tokenBody = @{
        client_id   = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Public Client ID (Microsoft Azure CLI)
        grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
        device_code = $authResponse.device_code
    }

    $armTokenResponse = $null
    $totalWaitTime = 0
    $continue = $true

    # Polling loop: keep requesting the token until the user authenticates or the token request expires
    while ($continue -and $totalWaitTime -lt $expiresIn) {
        Start-Sleep -Seconds $interval
        $totalWaitTime += $interval
        Write-Host "Waiting for device authentication... ($totalWaitTime seconds waited)" -ForegroundColor Yellow

        try {
            # Attempt to get the ARM token
            $armTokenResponse = Invoke-RestMethod -Method Post -Uri $tokenUrl -ContentType "application/x-www-form-urlencoded" -Body $tokenBody -ErrorAction Stop
            
            if ($armTokenResponse.access_token) {
                # Store the ARM token globally
                $global:ARMToken = $armTokenResponse.access_token
                Write-Host "Successfully authenticated for ARM! The ARM token is now available globally." -ForegroundColor Green
                $continue = $false  # Break the loop
                break  # Ensure immediate exit
            }
        } catch {
            # Handle expected "authorization_pending" errors while polling
            if ($_.ErrorDetails.Message) {
                $details = $_.ErrorDetails.Message | ConvertFrom-Json
                $continue = $details.error -eq "authorization_pending"
                Write-Output "$($details.error)"
        
                if (!$continue) {
                    # If error is not "authorization_pending", stop execution
                    Write-Error "Authentication failed: $($details.error_description)"
                    return $null
                }
            } else {
                # Handle unexpected errors
                Write-Error "Unexpected error while requesting ARM token: $_"
                return $null
            }
        }
    }
}

function Find-DangerousServicePrincipals {
    Write-Host "Checking for required roles or permissions..."

    # Define required roles
    $requiredRoles = @(
        "Application Administrator"
    )

    # Get current user's roles
    $headers = @{ Authorization = "Bearer $global:GraphAccessToken" }

    try {
        $rolesResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/memberOf" -Headers $headers
        $assignedRoles = $rolesResponse.value | Where-Object { $_.'@odata.type' -eq "#microsoft.graph.directoryRole" } | Select-Object -ExpandProperty displayName
    } catch {
        Write-Warning "Unable to retrieve role membership. You may not have sufficient permissions."
        return
    }

    # Check for Global Administrator
    if ($assignedRoles -contains "Global Administrator") {
        Write-Host "✅ You are a Global Administrator. Skipping role checks." -ForegroundColor Green
    } else {
        $missingRoles = $requiredRoles | Where-Object { $_ -notin $assignedRoles }

        if ($missingRoles.Count -gt 0) {
            Write-Warning "⚠️ You are missing the following roles required to run this function:"
            $missingRoles | ForEach-Object { Write-Host "- $_" }
            return
        } else {
            Write-Host "✅ Required roles confirmed. Proceeding..." -ForegroundColor Green
        }
    }

    Write-Host "Will search for Dangerous Permissions"

    # Get all Enterprise Applications (Service Principals)
    $enterpriseAppsUrl = "https://graph.microsoft.com/v1.0/servicePrincipals?$filter=servicePrincipalType eq 'Application'"
    try {
        $enterpriseApps = Invoke-RestMethod -Uri $enterpriseAppsUrl -Headers $headers -Method Get
    } catch {
        Write-Error "Failed to retrieve service principals: $_"
        return
    }

    Write-Host "Pulling all Enterprise Applications"

    # Output the results
    foreach ($app in $enterpriseApps.value) {
        if ($app.appDisplayName) {
            Get-DangerousPermissions -ServicePrincipalId $app.id -appDisplayName $app.appDisplayName
        } else {
            Get-DangerousPermissions -ServicePrincipalId $app.id
        }
    }

    # Handle pagination (check for nextLink)
    while ($enterpriseApps.'@odata.nextLink') {
        Write-Host "Checking next page of API requests"
        $nextUrl = $enterpriseApps.'@odata.nextLink'
        try {
            $enterpriseApps = Invoke-RestMethod -Uri $nextUrl -Headers $headers -Method Get
        } catch {
            Write-Error "Failed to retrieve next page of service principals: $_"
            break
        }

        foreach ($app in $enterpriseApps.value) {
            if ($app.appDisplayName) {
                Get-DangerousPermissions -ServicePrincipalId $app.id -appDisplayName $app.appDisplayName
            } else {
                Get-DangerousPermissions -ServicePrincipalId $app.id
            }
        }
    }
}


# Internal function to get dangerous permissions for Service Principals (hidden from help)
function Get-DangerousPermissions {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipalId,

        [Parameter(Mandatory = $false)]
        [string]$appDisplayName
    )

    # Capture the dangerous Service Principals
    $dangerousSPs = @()

    # Define the dangerous AppRole IDs
    $appRoleIdToPermissionName = @{
        "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" = "RoleManagement.ReadWrite.Directory"
        "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9" = "Application.ReadWrite.All"
        "741f803b-c850-494e-b5df-cde7c675a1ca" = "User.ReadWrite.All"
        "c529cfca-c91b-489c-af2b-d92990b66ce6" = "User.ManageIdentities.All"
        "06b708a9-e830-4db3-a914-8e69da51d44f" = "AppRoleAssignment.ReadWrite.All"
        "19dbc75e-c2e2-444c-a770-ec69d8559fc7" = "Directory.ReadWrite.All"
        "292d869f-3427-49a8-9dab-8c70152b74e9" = "Organization.ReadWrite.All"
        "29c18626-4985-4dcd-85c0-193eef327366" = "Policy.ReadWrite.AuthenticationMethod"
        "01c0a623-fc9b-48e9-b794-0756f8e8f067" = "Policy.ReadWrite.ConditionalAccess"
        "50483e42-d915-4231-9639-7fdb7fd190e5" = "UserAuthenticationMethod.ReadWrite.All"
        "810c84a8-4a9e-49e6-bf7d-12d183f40d01" = "Mail.Read"
        "b633e1c5-b582-4048-a93e-9f11b44c7e96" = "Mail.Send"
        "e2a3a72e-5f79-4c64-b1b1-878b674786c9" = "Mail.ReadWrite"
        "6931bccd-447a-43d1-b442-00a195474933" = "MailboxSettings.ReadWrite"
        "75359482-378d-4052-8f01-80520e7db3cd" = "Files.ReadWrite.All"
        "01d4889c-1287-42c6-ac1f-5d1e02578ef6" = "Files.Read.All"
        "332a536c-c7ef-4017-ab91-336970924f0d" = "Sites.Read.All"
        "9492366f-7969-46a4-8d15-ed1a20078fff" = "Sites.ReadWrite.All"
        "0c0bf378-bf22-4481-8f81-9e89a9b4960a" = "Sites.Manage.All"
        "a82116e5-55eb-4c41-a434-62fe8a61c773" = "Sites.FullControl.All"
        "3aeca27b-ee3a-4c2b-8ded-80376e2134a4" = "Notes.Read.All"
        "0c458cef-11f3-48c2-a568-c66751c238c0" = "Notes.ReadWrite.All"
        "9241abd9-d0e6-425a-bd4f-47ba86e767a4" = "DeviceManagementConfiguration.ReadWrite.All"
        "78145de6-330d-4800-a6ce-494ff2d33d07" = "DeviceManagementApps.ReadWrite.All"
    }
    $appRoleAssignmentsUrl = "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId/appRoleAssignments"
    $appRoleAssignments = Invoke-RestMethod -Uri $appRoleAssignmentsUrl -Headers @{ "Authorization" = "Bearer $global:GraphAccessToken" } -Method Get
    foreach ($assignment in $appRoleAssignments.value) {
        $appRoleId = $assignment.appRoleId
        # Write-Host "Testing AppRoleId $appRoleId"
        # Check if the appRoleId is in the dangerous roles
        if ($appRoleIdToPermissionName.ContainsKey($appRoleId)) {
            $permissionName = $appRoleIdToPermissionName[$appRoleId]
            # Write-Host "Testing $permissionName"
            Write-Host "[+] Service Principal $appDisplayName (SP ID: $ServicePrincipalId) has the dangerous permission: $permissionName" -ForegroundColor Red

            $dangerousSPs += [PSCustomObject]@{
                AppDisplayName      = $appDisplayName
                ServicePrincipalId  = $ServicePrincipalId
                DangerousPermissions = $permissionName
            } 
        if ($ExportSP){$dangerousSPs | Export-CSV -Path "$($global:ToolName)_DangerousServicePrincipals.csv" -NoTypeInformation -Append}
        } 
    }
}

# Internal function to find privileged role assignments (hidden from help)
function Find-PrivilegedRoleAssignments {
    Write-Host "Checking for required roles..."

    $headers = @{ Authorization = "Bearer $global:GraphAccessToken" }

    # Get current user's role memberships
    try {
        $rolesResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/memberOf" -Headers $headers
        $assignedRoles = $rolesResponse.value | Where-Object { $_.'@odata.type' -eq "#microsoft.graph.directoryRole" } | Select-Object -ExpandProperty displayName
    } catch {
        Write-Warning "Unable to retrieve role membership. You may not have sufficient permissions."
        return
    }

    # Check for required roles
    $requiredRoles = @("Privileged Role Administrator", "Global Administrator")
    $hasRequiredRole = $assignedRoles | Where-Object { $requiredRoles -contains $_ }

    if (-not $hasRequiredRole) {
        Write-Warning "⚠️ You do not have the required roles to access privileged role assignments."
        Write-Host "Required: Privileged Role Administrator or Global Administrator"
        Write-Host "Assigned: $($assignedRoles -join ', ')"
        return
    }

    Write-Host "✅ Required role confirmed. Proceeding with privileged role assignment scan..."

    $InterestingDirectoryRole = @{
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" = "Application Administrator"
        "158c047a-c907-4556-b7ef-446551a6b5f7" = "Cloud Application Administrator"
        "9360feb5-f418-4baa-8175-e2a00bac4301" = "Directory Writers"
        "62e90394-69f5-4237-9190-012177145e10" = "Global Administrator"
        "fdd7a751-b60b-444a-984c-02652fe8fa1c" = "Groups Administrator"
        "45d8d3c5-c802-45c6-b32a-1d70b5e1e86e" = "Identity Governance Administrator"
        "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2" = "Hybrid Identity Administrator"
        "3a2c62db-5318-420d-8d74-23affee5d9d5" = "Intune Administrator"
        "b5a8dcf3-09d5-43a9-a639-8e29ef291470" = "Knowledge Administrator"
        "4ba39ca4-527c-499a-b93d-d9b492c50246" = "Partner Tier1 Support"
        "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8" = "Partner Tier2 Support"
        "e8611ab8-c189-46e8-94e1-60213ab1f814" = "Privileged Role Administrator"
        "fe930be7-5e62-47db-91af-98c3a49a38b1" = "User Administrator"
        "11451d60-acb2-45eb-a7d6-43d0f0125c13" = "Windows 365 Administrator"
        "c4e39bd9-1100-46d3-8c65-fb160da0071f" = "Authentication Administrator"
        "b0f54661-2d74-4c50-afa3-1ec803f12efe" = "Billing administrator"
        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9" = "Conditional Access administrator"
        "29232cdf-9323-42fd-ade2-1d097af3e4de" = "Exchange administrator"
        "729827e3-9c14-49f7-bb1b-9608f156bbb8" = "Helpdesk administrator"
        "966707d0-3269-4727-9be2-8c3a10f19b9d" = "Password administrator"
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" = "Privileged authentication administrator"
        "194ae4cb-b126-40b2-bd5b-6091b380977d" = "Security administrator"
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c" = "SharePoint administrator"
    }

    # Fetch all role assignments
    $roleAssignmentsUrl = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
    try {
        $roleAssignmentsResponse = Invoke-RestMethod -Uri $roleAssignmentsUrl -Headers $headers -Method Get
        $roleAssignments = $roleAssignmentsResponse.value
    } catch {
        Write-Error "Failed to retrieve role assignments: $_"
        return
    }

    foreach ($assignment in $roleAssignments) {
        $roleId = $assignment.roleDefinitionId
        $principalId = $assignment.principalId

        if ($InterestingDirectoryRole.ContainsKey($roleId)) {
            $roleName = $InterestingDirectoryRole[$roleId]
            Get-PrivilegedRoleAssignments -PrincipalId $principalId -RoleName $roleName
        }
    }
}

function Get-PrivilegedRoleAssignments {
    param (
        [Parameter(Mandatory = $true)]
        [string]$PrincipalId,

        [Parameter(Mandatory = $true)]
        [string]$RoleName
    )

    # API URLs to check if the principal is an SP, User, or Group
    $spUrl = "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId"
    $userUrl = "https://graph.microsoft.com/v1.0/users/$PrincipalId"
    $groupUrl = "https://graph.microsoft.com/v1.0/groups/$PrincipalId"

    try {
        $spDetails = Invoke-RestMethod -Uri $spUrl -Headers @{ "Authorization" = "Bearer $global:GraphAccessToken" } -Method Get -ErrorAction Stop
        Write-Host "[+] Service Principal $($spDetails.displayName) (SP ID: $PrincipalId) has privileged role: $RoleName" -ForegroundColor Red
    }
    catch {
        try {
            $userDetails = Invoke-RestMethod -Uri $userUrl -Headers @{ "Authorization" = "Bearer $global:GraphAccessToken" } -Method Get -ErrorAction Stop
            #Write-Host "[+] User $($userDetails.displayName) (User ID: $PrincipalId) has privileged role: $RoleName" -ForegroundColor Yellow
        }
        catch {
            try {
                $groupDetails = Invoke-RestMethod -Uri $groupUrl -Headers @{ "Authorization" = "Bearer $global:GraphAccessToken" } -Method Get -ErrorAction Stop
                Write-Host "[+] Group $($groupDetails.displayName) (Group ID: $PrincipalId) has privileged role: $RoleName" -ForegroundColor Cyan
            }
            catch {
                Write-Host "[-] Unable to retrieve details for Principal ID: $PrincipalId (Assigned Role: $RoleName)" -ForegroundColor DarkGray
            }
        }
    }
}


function Get-AllPages {
    param (
        [Parameter(Mandatory = $true)]
        [string]$InitialUrl,
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers
    )

    $allResults = @()
    try {
        $response = Invoke-RestMethod -Uri $InitialUrl -Headers $Headers -Method Get -ErrorAction Stop
        $allResults += $response.value
    } catch {
        Write-Host "❌ Error retrieving API data: $_" -ForegroundColor Red
        return @()
    }

    while ($response.'@odata.nextLink') {
        Write-Host "🔄 Fetching next page of API results..." -ForegroundColor Yellow
        try {
            $response = Invoke-RestMethod -Uri $response.'@odata.nextLink' -Headers $Headers -Method Get -ErrorAction Stop
            $allResults += $response.value
        } catch {
            Write-Host "⚠️ Warning: Failed to fetch next page of API results." -ForegroundColor Yellow
            break
        }
    }

    return $allResults
}

function Get-PrincipalDetails {
    param (
        [Parameter(Mandatory = $true)]
        [string]$PrincipalId
    )

    if (-not $Global:GraphAccessToken) {
        Write-Host "❌ Graph API Token not found. Please run Get-MicrosoftGraphToken first." -ForegroundColor Red
        return $null
    }

    $graphHeaders = @{ "Authorization" = "Bearer $Global:GraphAccessToken" }

    try {
        $url = "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId"
        $spDetails = Invoke-RestMethod -Uri $url -Headers $graphHeaders -Method Get -ErrorAction Stop
        return $spDetails
    } catch {
        Write-Host "⚠️ Unable to retrieve details for Principal ID: $PrincipalId" -ForegroundColor Yellow
        return $null
    }
}

function Find-SubscriptionOwnersContributors {
    Write-Host "[*] Retrieving all Azure Subscriptions..." -ForegroundColor Cyan

    if (-not $Global:ARMToken) {
        Write-Host "❌ ARM Token not found. Please run Get-ARMToken first." -ForegroundColor Red
        return
    }

    $subscriptionsUrl = "https://management.azure.com/subscriptions?api-version=2020-01-01"
    $headers = @{ "Authorization" = "Bearer $Global:ARMToken" }

    try {
        $subscriptions = Invoke-RestMethod -Uri $subscriptionsUrl -Headers $headers -Method Get -ErrorAction Stop
    } catch {
        Write-Host "❌ Failed to retrieve subscriptions: $_" -ForegroundColor Red
        return
    }

    $subscriptions = $subscriptions.value

    # ✅ Subscription Roles (Only Owner & Contributor)
    $subscriptionRoles = @{
        "8e3af657-a8ff-443c-a75c-2fe8c4bcb635" = "Owner"
        "b24988ac-6180-42a0-ab88-20f7382dd24c" = "Contributor"
    }

    $results = @()

    foreach ($subscription in $subscriptions) {
        $subscriptionId = $subscription.subscriptionId
        $subscriptionName = $subscription.displayName
        Write-Host "[*] Checking Subscription: $subscriptionName ($subscriptionId)" -ForegroundColor Yellow

        $roleAssignmentsUrl = "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
        $roleAssignments = Get-AllPages -InitialUrl $roleAssignmentsUrl -Headers $headers

        foreach ($assignment in $roleAssignments) {
            $roleId = $assignment.properties.roleDefinitionId -replace '.*/', ''  # Extract GUID
            $principalId = $assignment.properties.principalId
            $principalType = $assignment.properties.principalType  # Can be ServicePrincipal, ManagedIdentity, User, Group

            # Include only SPs and MIs
            if ($principalType -eq "ServicePrincipal" -or $principalType -eq "ManagedIdentity") {
                if ($null -ne $roleId -and $subscriptionRoles.ContainsKey($roleId)) {
                    $roleName = $subscriptionRoles[$roleId]

                    # Ensure Principal Details are Retrieved
                    $principalDetails = Get-PrincipalDetails -PrincipalId $principalId
                    if ($principalDetails) {
                        # Determine if it's a Managed Identity or standard Service Principal
                        $spType = $principalDetails.servicePrincipalType
                        $principalLabel = if ($spType -eq "ManagedIdentity") { "(MI)" } else { "(SP)" }
                        $formattedPrincipalName = "$($principalDetails.displayName) $principalLabel"

                        $results += [PSCustomObject]@{
                            SubscriptionName  = $subscriptionName
                            PrincipalName     = $formattedPrincipalName
                            Role              = $roleName
                        }
                    }
                }
            }
        }
    }

    if ($results.Count -gt 0) {
        Write-Host "`n[+] Found the following SPs & MIs with Owner or Contributor roles on Subscriptions:" -ForegroundColor Green
        $results | Format-Table -Property SubscriptionName, PrincipalName, Role -AutoSize
    } else {
        Write-Host "`n[-] No Service Principals or Managed Identities found with Owner/Contributor roles on Subscriptions." -ForegroundColor Red
    }
}
