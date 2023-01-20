function Write-Log
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Message
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "$timestamp - $Message"
}

function Connect{
    try {
        Connect-MgGraph -ClientID $AppID -TenantId $TenantID -CertificateThumbprint $Cert
    }
    catch {
        Write-Host -ForegroundColor red "Could not connect!"
        Write-Host -ForegroundColor red $_.Exception.Message
    }
    

}

Function Get-UnusedLicenseReport{
    param(
        [parameter(Mandatory = $true)][string]$CSVPath,
        [parameter(Mandatory = $true)][string]$OrgName
    )
    try {
        $Path = $CSVPath + "\unusedlicense.csv"
        
        $LicensePackages = Get-MGSubscribedSku
        $Data = [System.Collections.Generic.List[Object]]::new()
        foreach($LicensePackage in $LicensePackages)
        {
            $LicenseLine = [PSCustomObject][Ordered]@{
                AccountSkuId = $OrgName+':'+$LicensePackage.SkuPartNumber
                ActiveUnits = $LicensePackage.PrepaidUnits.Enabled
                ConsumedUnits = $LicensePackage.ConsumedUnits
                LockedOutUnits =  $LicensePackage.PrepaidUnits.Suspended                
            }
            $Data.Add($LicenseLine)   
        }
        $Data | Sort-Object SkuPartNumber |Export-Csv -Path $Path -Append -NoTypeInformation
      
    }
    catch {
        Write-Host -ForegroundColor red "Error getting unlicensed users"
        Write-Host -ForegroundColor red $_.Exception.Message
    }
}


Function Get-GraphReports {
    param(
        [parameter(Mandatory = $true)][string]$CSVPath,
        [parameter(Mandatory = $true)][string]$ReportPeriod
    )
    
    try {
        Write-Host -ForegroundColor green "- getTeamsUserActivityUserDetail.csv..."
       Get-MgReportTeamUserActivityUserDetail -Period $ReportPeriod -OutFile "$OutPutPath\getTeamsUserActivityUserDetail.csv"

       Write-Host -ForegroundColor green "- getOffice365ActiveUserDetail.csv..."
       Get-MgReportOffice365ActiveUserDetail -Period $ReportPeriod -OutFile "$OutPutPath\getOffice365ActiveUserDetail.csv"

       Write-Host -ForegroundColor green "- getOffice365GroupsActivityDetail.csv..."
       Get-MgReportOffice365GroupActivityDetail -Period $ReportPeriod -OutFile "$OutPutPath\getOffice365GroupsActivityDetail.csv"   
       
       Write-Host -ForegroundColor green "- getYammerActivityUserDetail.csv..."
       Get-MgReportYammerActivityUserDetail -Period $ReportPeriod -OutFile "$OutPutPath\getYammerActivityUserDetail.csv" 

       Write-Host -ForegroundColor green "- getSkypeForBusinessActivityUserDetail.csv..."
       Get-MgReportSkypeForBusinessActivityUserDetail -Period $ReportPeriod -OutFile "$OutPutPath\getSkypeForBusinessActivityUserDetail.csv"
        

       Write-Host -ForegroundColor green "- getOneDriveActivityUserDetail.csv..."
       Get-MgReportOneDriveActivityUserDetail -Period $ReportPeriod -OutFile "$OutPutPath\getOneDriveActivityUserDetail.csv"

       Write-Host -ForegroundColor green "- getEmailActivityUserDetail.csv..."
       Get-MgReportEmailActivityUserDetail -Period $ReportPeriod -OutFile "$OutPutPath\getEmailActivityUserDetail.csv"

       Write-Host -ForegroundColor green "- getOneDriveUsageAccountDetail.csv..."
       Get-MgReportOneDriveUsageAccountDetail -Period $ReportPeriod -OutFile "$OutPutPath\getOneDriveUsageAccountDetail.csv"

       Write-Host -ForegroundColor green "- getSharePointActivityUserDetail.csv..."
       Get-MgReportSharePointActivityUserDetail -Period $ReportPeriod -OutFile "$OutPutPath\getSharePointActivityUserDetail.csv"

       Write-Host -ForegroundColor green "- getMailboxUsageDetail.csv..."
       Get-MgReportMailboxUsageDetail -Period $ReportPeriod -OutFile "$OutPutPath\getMailboxUsageDetail.csv"

       Write-Host -ForegroundColor green "- getOffice365ActivationsUserCounts.csv..."
       Get-MgReportOffice365ActiveUserCount -Period $ReportPeriod -OutFile "$OutPutPath\getOffice365ActivationsUserCounts.csv"

       Write-Host -ForegroundColor green "- getOffice365ActivationsUserDetail.csv..."
       Get-MgReportOffice365ActivationUserDetail  -OutFile "$OutPutPath\getOffice365ActivationsUserDetail.csv"

       Write-Host -ForegroundColor green "- getOffice365ServicesUserCounts.csv..."
       Get-MgReportOffice365ServiceUserCount -Period $ReportPeriod -OutFile "$OutPutPath\getOffice365ServicesUserCounts.csv"
    }
    catch {
        Write-Host -ForegroundColor red "Error generating reports"
        Write-Host -ForegroundColor red $_.Exception.Message
    }
}

Function Get-LoginLogs {
    [cmdletbinding()]
    param(
       [parameter(Mandatory = $true)][string]$CSVPath
    )   

    $Applications = "Power BI Premium",
    "Microsoft Planner",
    "Office Sway", 
    "Microsoft To-Do",
    "Microsoft Stream",
    "Microsoft Forms",
    "Microsoft Cloud App Security",
    "Project Online",
    "Dynamics CRM Online",
    "Azure Advanced Threat Protection",
    "Microsoft Flow"
    $PastDays = 90
    $today = Get-Date -Format "yyyy-MM-dd"
    $PastPeriod = ("{0:s}" -f (get-date).AddDays( - ($PastDays))).Split("T")[0]
    

    foreach ($app in $Applications) {
        Try {
                $filter = "createdDateTime ge " + $PastPeriod + "T00:00:00Z and createdDateTime le " + $today + "T00:00:00Z and (appId eq '" + $app + "' or startswith(appDisplayName,'" + $app + "'))"        
                $reportname = "Audit-" + $app        
                Write-host -ForegroundColor green "- $reportname ..." 
                $myReport = Get-MgAuditLogSignIn -Filter $filter
               
               if($myReport){
                $myReport | ConvertTo-Csv -NoTypeInformation | Add-Content "$CSVPath\$reportname.csv"
               }
               else {
                    $myReport ='"id","createdDateTime","userDisplayName","userPrincipalName","userId","appId","appDisplayName","ipAddress","clientAppUsed","correlationId","conditionalAccessStatus","originalRequestId","isInteractive","tokenIssuerName","tokenIssuerType","processingTimeInMilliseconds","riskDetail","riskLevelAggregated","riskLevelDuringSignIn","riskState","riskEventTypes","resourceDisplayName","resourceId","authenticationMethodsUsed","mfaDetail","status","deviceDetail","location","appliedConditionalAccessPolicies","authenticationProcessingDetails","networkLocationDetails"'
                    $myReport | Add-Content "$CSVPath\$reportname.csv"
               }     
        }
        Catch{
            Write-Host -ForegroundColor red "Error generating reports"
            Write-Host -ForegroundColor red $_.Exception.Message
        }
    }
}


Function Get-All-Users{
    [cmdletbinding()]
    param(
       [parameter(Mandatory = $true)][string]$CSVPath
    )  

    try {

        $props = @( 'userType', 
                    'AccountEnabled', 
                    'AgeGroup',
                    'AssignedLicenses', 
                    'AssignedLicenses', 
                    'UserPrincipalName', 
                    'city', 
                    "CompanyName",
                    "consentProvidedForMinor",
                    "Country",
                    "creationType",
                    "department",
                    "displayName",
                    "faxNumber",
                    "givenName",
                    "onPremisesImmutableId",
                    "onPremisesSyncEnabled",
                    "jobTitle",
                    "onPremisesLastSyncDateTime",
                    "legalAgeGroupClassification",
                    "mail",
                    "mailNickname",
                    "mobilePhone",
                    "otherMails",
                    "onPremisesSecurityIdentifier",
                    "passwordPolicies",
                    "passwordProfile",
                    "officeLocation",
                    "postalCode",
                    "preferredLanguage",
                    "provisionedPlans",
                    "proxyAddresses",
                    "refreshTokensValidFromDateTime",
                    "showInAddressList",
                    "imAddresses",
                    "state",
                    "streetAddress",
                    "surname",
                    "usageLocation",
                    "state"

                )
        
       $users =  Get-MgUser -All -Property $props # | Export-Csv -Path $CSVPath\"AllUser.csv" -NoTypeInformation    
        #Get-AzureADUser -All:$true | Export-Csv -Path $OutPutPath"\AllUser.csv" -NoTypeInformation
        $userObj = foreach($user in $users){
            [PSCustomObject]@{
                "ExtensionProperty" = ""
                "DeletionTimestamp" = ""
                "ObjectId" = $user.id
                "ObjectType" = $user.userType
                "AccountEnabled" = $user.AccountEnabled
                "AgeGroup" = $user.AgeGroup
                "AssignedLicenses" = $user.AssignedLicenses
                "AssignedPlans" = $user.assignedPlans
                "City" = $user.city
                "CompanyName" = $user.CompanyName
                "ConsentProvidedForMinor" = $user.consentProvidedForMinor
                "Country" = $user.country 
                "CreationType" = $user.creationType
                "Department" = $user.department
                "DirSyncEnabled" = $user.onPremisesSyncEnabled
                "DisplayName" = $user.displayName
                "FacsimileTelephoneNumber" = $user.faxNumber 
                "GivenName" = $user.givenName
                "IsCompromised" = ""
                "ImmutableId" = $user.onPremisesImmutableId
                "JobTitle" = $user.jobTitle 
                "LastDirSyncTime" = $user.onPremisesLastSyncDateTime
                "LegalAgeGroupClassification" = $user.legalAgeGroupClassification 
                "Mail" = $user.mail
                "MailNickName" = $user.mailNickname
                "Mobile" = $user.mobilePhone
                "OnPremisesSecurityIdentifier" = $user.onPremisesSecurityIdentifier 
                "OtherMails" = $user.otherMails 
                "PasswordPolicies" = $user.passwordPolicies
                "PasswordProfile" = $user.passwordProfile
                "PhysicalDeliveryOfficeName" = $user.officeLocation 
                "PostalCode" = $user.postalCode 
                "PreferredLanguage" = $user.preferredLanguage
                 "ProvisionedPlans" = $user.provisionedPlans
                "ProvisioningErrors" = ""
                "ProxyAddresses" = $user.proxyAddresses
                "RefreshTokensValidFromDateTime" = $user.refreshTokensValidFromDateTime
                "ShowInAddressList" = $user.showInAddressList
                "SignInNames" = ""
                "SipProxyAddress" = $user.imAddresses
                "State" = $user.state
                "StreetAddress" = $user.streetAddress
                "Surname" = $user.surname
                "TelephoneNumber" = ""
                "UsageLocation" = $user.usageLocation
                "UserPrincipalName" = $user.userPrincipalName
                "UserState" = $user.state
                "UserStateChangedOn" = $user.externalUserStateChangeDateTime
                "UserType" = $user.userType
            }
        }
        $userObj | Export-Csv -Path $CSVPath\"AllUser.csv" -NoTypeInformation 
    }
    catch {
        Write-Host -ForegroundColor red "Error generating reports"
        Write-Host -ForegroundColor red $_.Exception.Message
    }
}


function Get-AssignedPlans{
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)][string]$CSVPath,
        [parameter(Mandatory = $true)][string]$OrgName
    )
    $reportname = "\assignedPlans"
    $Path = $CSVPath + $reportname + ".csv"
    $props = @('AssignedLicenses', 'UserPrincipalName' )

    $mgUsers = Get-MgUser -Filter 'assignedLicenses/$count ne 0' -ConsistencyLevel eventual -CountVariable licensedUserCount -All -Property $props | Select-Object $props
    #$mgUsers
    $skus = Get-MgSubscribedSku
    $skuHt = @{}
    foreach ($sku in $skus) {
     $skuHt[$sku.SkuId] = $sku
    }

    $userOutput = foreach ($user in $mgUsers) {    
        $licenses = foreach($license in $user.AssignedLicenses) {
        $skuHt[$license.SkuId].SkuPartNumber
    }
    $user | Add-Member -MemberType NoteProperty -Name licenses -Value ($OrgName+":"+$licenses -join ',')
    $user | Select-Object -Property 'licenses', 'UserPrincipalName'
   }
   $userOutput | Export-Csv -Path $Path -NoTypeInformation
} 

function Get-LicensingGroups{
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)][string]$CSVPath
    )
    $reportname = "\LicensingGroups"
    $Path = $CSVPath + $reportname + ".csv"
    
  
    $props = @('id', 'DisplayName', 'licenseAssignmentStates', 'assignedLicenses' )
    $groups = Get-MgGroup -All -Property $props

    $skusHash = @{} # An empty hashtable
    ##Get all available SKUs
    Get-MgSubscribedSku | ForEach-Object {
        $DisplayName = $_.SkuPartNumber 
       
        $_ | Add-Member -MemberType NoteProperty -Name DisplayName -Value $DisplayName
        $skusHash[$_.SkuId] = $_
    } 

 

    foreach($group in  $groups){
        $groupId = $group.id
        $groupName = $group.DisplayName
        $hasLicenses = $group.assignedLicenses
    
        $licenseString = ""
        if($hasLicenses){                     
            foreach($license in $hasLicenses ){            
                $licenseString +=  $skusHash[$license.SkuId].DisplayName +";"
            }
          
            $members = Get-MgGroupMember -GroupId $groupId -All
           
            $owners = Get-MgGroupOwner -GroupId $groupId -All

            $allOwners = foreach($owner in $owners){
               $o = get-mguser -UserId $owner.Id
               [PSCustomObject]@{
                    GroupLicense = $LicenseString
                    GroupName = $groupName
                    GroupId = $groupId
                    ExtensionData = ""
                    CommonName = $o.givenName
                    DisplayName = $o.displayName
                    EmailAddress = $o.UserPrincipalName
                    GroupMemberType = "Owner"
                    IsLicensed = "TRUE"
                    LastDirSyncTime = ""
                    ObjectId = $o.Id
                    OverallProvisioningStatus = ""
                    ValidationStatus = ""
               }
            }

            $allOwners | Select-Object -Property * | Export-Csv $Path -Append -NoTypeInformation
            
            $allUsers =  foreach($member in $members){
               $user =get-mguser -UserId $member.Id
               [PSCustomObject]@{
                    GroupLicense = $LicenseString
                    GroupName = $groupName
                    GroupId = $groupId
                    ExtensionData = ""
                    CommonName = $user.givenName
                    DisplayName = $user.displayName
                    EmailAddress = $user.UserPrincipalName
                    GroupMemberType = "Member"
                    IsLicensed = "TRUE"
                    LastDirSyncTime = ""
                    ObjectId = $member.Id
                    OverallProvisioningStatus = ""
                    ValidationStatus = ""
                }
            }

            $allUsers | Select-Object -Property * | Export-Csv $Path -Append -NoTypeInformation

        }        
    }   
} 

Function Get-LicenseAssignmentPath{
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)][string]$CSVPath
    )
    $reportname = "\LicenseAssignmentPath"
    $Path = $CSVPath + $reportname + ".csv"    
    $props = @('LicenseAssignmentStates','id', 'UserPrincipalName' )
    $users = Get-MgUser -All -Property $props
    $groupGUIDs = $users.LicenseAssignmentStates.assignedByGroup | Select-Object -unique    
    $assignmentGroup = ($groupGUIDs | ForEach-Object {Get-MgGroup -GroupId $_}).DisplayName 
   
    $skusHash = @{} # An empty hashtable
    ##Get all available SKUs
    Get-MgSubscribedSku | ForEach-Object {
        $DisplayName = $_.SkuPartNumber 
        $_ | Add-Member -MemberType NoteProperty -Name DisplayName -Value $DisplayName
        $skusHash[$_.SkuId] = $_
    }
    $report = foreach ($user in $users) {
        if ($user.LicenseAssignmentStates) { 
            foreach ($assignment in $user.LicenseAssignmentStates) {
                $assignedLicenseName = $skusHash[$assignment.SkuId].DisplayName                
                if (-Not $assignedLicenseName) { continue } # This is a zombie license that is not showing in Azure AD purchased SKUs.
     
                if ($assignment.AssignedByGroup) {
                    $assignedDirectly = $False
                    $assignmentGroup = $True
                }
                else {
                    # Direct License Assignment
                    $assignedDirectly = $True
                    $assignmentGroup = $False
                }
                [PSCustomObject]@{
                    ObjectId              = $user.Id
                    UserPrincipalName  = $user.UserPrincipalName
                    AssignedDirectly   = $assignedDirectly
                    AssignedFromGroup  = $assignmentGroup
                    SKU                = $assignedLicenseName                 
                }   
            }
        }
        else {
            # user does not have any assigned license
            [PSCustomObject]@{
                ObjectId              = $user.Id
                UserPrincipalName  = $user.UserPrincipalName
                AssignedDirectly   = $null 
                AssignedFromGroup  = $null
                SKU                = $null                                  
            }
        }
    }
    $report | Export-Csv $path -Append -NoTypeInformation
}

Function Get-AdminReport{
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)][string]$CSVPath
    )
    $reportname = "\AdminReport"
    $path = $CSVPath + $reportname + ".csv"
    $allAdminRole = Get-MgDirectoryRole 
    $props = @('LicenseAssignmentStates','DisplayName', 'UserPrincipalName' )
    
    $skusHash = @{} # An empty hashtable
    ##Get all available SKUs
    Get-MgSubscribedSku | ForEach-Object {
        $DisplayName = $_.SkuPartNumber 
        $_ | Add-Member -MemberType NoteProperty -Name DisplayName -Value $DisplayName
        $skusHash[$_.SkuId] = $_
    }

    $report = foreach($role in $allAdminRole){
        $roleID = $Role.Id
        $roleDisplayName = $role.DisplayName       
        $admins = Get-MgDirectoryRoleMember  -DirectoryRoleId $roleID 
        foreach ($admin in $admins){
            
            $user = Get-MgUser -UserId $admin.id -Property $props
            $allLicenses = Get-MgUserLicenseDetail -UserId $admin.id -Property SkuPartNumber, ServicePlans
        
            $assignedLicenseName = @()
            $allLicenses | ForEach-Object {
                $assignedLicenseName += $_.SkuPartNumber+";"                
            } 

            if($assignedLicenseName.Length -gt 0){
                $isLicensed = $true
            }
            else{
                $isLicensed = $False
            }
           
            [PSCustomObject]@{
                Adminrole = $roleDisplayName
                Licenses = $assignedLicenseName
                DisplayName = $user.DisplayName
                IsLicensed = $isLicensed                
                UPN = $user.UserPrincipalName
            } 
        }
    }
    $report | Select-Object -Property * | Export-Csv -notypeinformation -Path $Path 
} 



###### End Functions  #############################
if ($MyInvocation.MyCommand.CommandType -eq "ExternalScript")
 { $ScriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition }
 else
 { $ScriptPath = Split-Path -Parent -Path ([Environment]::GetCommandLineArgs()[0]) 
     if (!$ScriptPath){ $ScriptPath = "." } }

     

#Config file path
$Configfile = Join-Path $ScriptPath -ChildPath "\Config\config.json"
##$Configfile = Join-Path $PSScriptRoot -ChildPath "\Config\config.json"

#Import variables from config file
$Config = Get-Content $Configfile |ConvertFrom-Json
$AppId = $Config.Tenant.AppId
$TenantId = $Config.Tenant.TenantId
$Cert = $Config.Tenant.CertificateThumbprint

#Define output path, if the folder does not exisit it will be created
$OutPutPath = "Output"
if (-Not (Test-Path -Path $OutPutPath)) {
    New-Item -ItemType directory -Path  $OutPutPath
} 

#Removes all old files from the output folder
Write-Log -Message 'Removing old files'
Get-ChildItem -Path $OutPutPath -Filter *.csv | Remove-Item
Get-ChildItem -Path $OutPutPath -Filter *.txt | Remove-Item




#If the Microsoft Graph module is not installed the script will exit.
Write-Log -Message 'Checking for required modules '
$graph_version = Get-InstalledModule Microsoft.Graph
if ($graph_version) {
    Import-Module Microsoft.Graph.Reports  
    Write-Host -ForegroundColor green '- Microsoft.Graph version:  '$graph_version.Version' is installed'
    Write-Log -Message "Connecting..."
    Connect
    
    #Get the organisation information and store the display name in a variable
    $Org = Get-MgOrganization
    $OrgName = $Org.DisplayName
    
 
    # Get Unlicensed users and save to the output path
    Write-Log -Message "Generating  Unused Licenses ..."
    Get-UnusedLicenseReport -CSVPath $OutPutPath -OrgName $OrgName
    
    #Generate Graph Reports
    Write-Log -Message "Generating reports"
    Get-GraphReports -CSVPath $OutPutPath -ReportPeriod "D180"

    #Generate Audit reports
    Write-Log -Message "Generating audit reports"
    Get-LoginLogs -CSVPath $OutPutPath

    #Export user list
    Write-Log -Message "Generating Azure AD Users"
    Get-All-Users -CSVPath $OutPutPath

    #Generate assigned plans
    Write-Log -Message "Generating assigned plans"
    Get-AssignedPlans -CSVPath $OutPutPath -OrgName $OrgName

    #Get licensing groups
    Write-Log -Message "Getting Licensing groups"    
    Get-LicensingGroups -CSVPath $OutPutPath


    Write-Log -Message "Getting License Assignment Path" 
    Get-LicenseAssignmentPath -CSVPath $OutPutPath


    Write-Log -Message "Getting Admin Report" 
    Get-AdminReport -CSVPath $OutPutPath

    Write-Log -Message "Disconnecting..."
    Disconnect-MgGraph | out-null
}
else {
    Write-Log -Message "[ERROR] Unable to Required Module!"
    Write-Log -Message "[ERROR] Please review documentation before proceeding!"
    exit
}


