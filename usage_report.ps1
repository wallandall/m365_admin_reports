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


    #3 Get-LoginLogs -ClientID $ClientID -redirectUri $redirectUri -tenantId $TenantID
    #4 Get-AzureADUser -All:$true | Export-Csv -Path $OutPutPath"\AllUser.csv" -NoTypeInformation
    #5 Get-AssignedPlans -CSVPath $OutPutPath
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


