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
    Connect-MgGraph -ClientID $AppID -TenantId $TenantID -CertificateName YOUR_CERT_SUBJECT

}




###### End Functions  #############################

#Config file path
$Configfile = Join-Path $PSScriptRoot -ChildPath "\Config\config.json"
#Import variables
$Config = Get-Content $Configfile |ConvertFrom-Json
$SubscriptionId = $Config.Tenant.TenantId


Write-Log -Message 'Checking for required modules'
#$graph_version = Get-Module -ListAvailable -Name 'Microsoft.Graph'
$graph_version = Get-InstalledModule Microsoft.Graph
if ($graph_version) {
    Write-Host -ForegroundColor green 'Microsoft.Graph version:  '$graph_version.Version' is installed'
    Write-Log "Connecting....."
    Write-Host $SubscriptionId
}
else {
    Write-Log "[ERROR] Unable to Required Module!"
    Write-Log "[ERROR] Please review documentation before proceeding!"
    exit
}


# Authenticate
#Connect-MgGraph -ClientID YOUR_APP_ID -TenantId YOUR_TENANT_ID -CertificateName YOUR_CERT_SUBJECT