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
        
        Get-MgUser -All | Export-Csv -Path $CSVPath\"AllUser.csv" -NoTypeInformation    
        #Get-AzureADUser -All:$true | Export-Csv -Path $OutPutPath"\AllUser.csv" -NoTypeInformation
    }
    catch {
        Write-Host -ForegroundColor red "Error generating reports"
        Write-Host -ForegroundColor red $_.Exception.Message
    }
}


function Get-AssignedPlans{
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)][string]$CSVPath
    )
    $reportname = "\assignedPlans"
    $Path = $CSVPath + $reportname + ".csv"
 
    $props = @(
      'AssignedLicenses', 'UserPrincipalName'
   )

   $mgUsers = Get-MgUser -Filter 'assignedLicenses/$count ne 0' -ConsistencyLevel eventual -CountVariable licensedUserCount -All -Property $props | Select-Object $props

   # Get the SKUs
   $skus = Get-MgSubscribedSku

   # Build a hashtable for faster lookups
   $skuHt = @{}
   foreach ($sku in $skus) {
     $skuHt[$sku.SkuId] = $sku
   }

   $userOutput = foreach ($user in $mgUsers) {

     # Resolve the ID to license name
     $licenses = foreach($license in $user.AssignedLicenses) {
          $skuHt[$license.SkuId].SkuPartNumber
    }

    $user | Add-Member -MemberType NoteProperty -Name Licenses -Value ($licenses -join ',')
    $user | Select-Object -Property 'Licenses', 'UserPrincipalName'
    
   }
  
   $userOutput | Export-Csv -Path $Path -NoTypeInformation

} 

###### End Functions  #############################

#Config file path
$Configfile = Join-Path $PSScriptRoot -ChildPath "\Config\config.json"

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
    ##Write-Log -Message "Generating  Unused Licenses ..."
    ##Get-UnusedLicenseReport -CSVPath $OutPutPath -OrgName $OrgName
    
    #Generate Graph Reports
    ##Write-Log -Message "Generating reports"
    ##Get-GraphReports -CSVPath $OutPutPath -ReportPeriod "D180"

    #Generate Audit reports
    ##Write-Log -Message "Generating audit reports"
   ## Get-LoginLogs -CSVPath $OutPutPath

    #Export user list
    ##Write-Log -Message "Generating Azure AD Users"
    ##Get-All-Users -CSVPath $OutPutPath

    #Generate assigned plans
    Write-Log -Message "Generating assigned plans"
    Get-AssignedPlans -CSVPath $OutPutPath
    #6 Get-LicensingGroups -CSVPath $OutPutPath
    #7 Get-LicenseAssignmentPath -CSVPath $OutPutPath
    #8 Get-AdminReport -CSVPath $OutPutPath

  




    

    Write-Log -Message "Disconnecting..."
    Disconnect-MgGraph | out-null
}
else {
    Write-Log -Message "[ERROR] Unable to Required Module!"
    Write-Log -Message "[ERROR] Please review documentation before proceeding!"
    exit
}


