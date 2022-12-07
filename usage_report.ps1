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
        Write-Host "Error getting unlicensed users"
        Write-Host $_.Exception.Message
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

#Removes all old files from the output folder
Write-Log -Message 'Removing old files'
Get-ChildItem -Path $OutPutPath -Filter *.csv | Remove-Item
Get-ChildItem -Path $OutPutPath -Filter *.txt | Remove-Item

#Define output path, if the folder does not exisit it will be created
$OutPutPath = "Output"
if (-Not (Test-Path -Path $OutPutPath)) {
    New-Item -ItemType directory -Path  $OutPutPath
} 


#If the Microsoft Graph module is not installed the script will exit.
Write-Log -Message 'Checking for required modules'
$graph_version = Get-InstalledModule Microsoft.Graph
if ($graph_version) {
    Write-Host -ForegroundColor green 'Microsoft.Graph version:  '$graph_version.Version' is installed'
    Write-Log "Connecting..."
    Connect
    
    #Get the organisation information and store the display name in a variable
    $Org = Get-MgOrganization
    $OrgName = $Org.DisplayName

    

    
    ##Get-MgContext
    
 
    # Get Unlicensed users and save to the output path
    Write-Log "Getting unused licenses..."
    Get-UnusedLicenseReport -CSVPath $OutPutPath -OrgName $OrgName
    #2 Get-GraphReports
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
    Write-Log "[ERROR] Unable to Required Module!"
    Write-Log "[ERROR] Please review documentation before proceeding!"
    exit
}


# Authenticate
#Connect-MgGraph -ClientID YOUR_APP_ID -TenantId YOUR_TENANT_ID -CertificateName YOUR_CERT_SUBJECT