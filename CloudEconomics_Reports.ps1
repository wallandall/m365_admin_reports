Function Expand-Collections {
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeline)]
        [psobject]$MSGraphObject
    )
    Begin {
        $IsSchemaObtained = $False
    }
    Process {
        If (!$IsSchemaObtained) {
            $OutputOrder = $MSGraphObject.psobject.properties.name
            $IsSchemaObtained = $True
        }

        $MSGraphObject | ForEach-Object {
            $singleGraphObject = $_
            $ExpandedObject = New-Object -TypeName PSObject

            $OutputOrder | ForEach-Object {
                Add-Member -InputObject $ExpandedObject -MemberType NoteProperty -Name $_ -Value $(($singleGraphObject.$($_) | Out-String).Trim())
            }
            $ExpandedObject
        }
    }
    End {}
}
Function Get-AccessToken {
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)][string]$TenantID,
        [parameter(Mandatory = $true)][string]$ClientID,
        [parameter(Mandatory = $true)][string]$redirectUri,
        [parameter(Mandatory = $true)][string]$resourceAppIdURI
    )   
    try {
        $Body = @{ grant_type = "client_credentials"; 
        resource = $resourceAppIdURI;
        client_id = $clientId; 
        client_secret = $Secret 
    }
        $authResult = Invoke-RestMethod -Method Post -Uri "$($loginurl)/$($TenantID)/oauth2/token?api-version=1.0" -Body $Body
        return $authResult
    }
    catch {
        Write-Host "Fehler bei Aufbau des AuthContext" 
        Write-Host $_.Exception.Message
    }
}
Function Test-Prerequisits{
    try {
        if (Get-Module -ListAvailable -Name 'MSOnline') {
            Import-Module MSOnline
        }else {
            if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                            if ($PSVersiontable.PSVersion.Major -ge 5) {
                               Install-Module MSOnline -Confirm:$true
                            }      else {
                                Write-Host "Bitte installieren Sie die Module manuell, da die PowerShell Version keine automatisierte Installation zulässt (PowerShell Version < 5)"
                            }
            }
            else {
                Write-Host "Bitte starten Sie die PowerShell als lokaler Admin und installieren Sie das Po$werShell Module MSOnline"
            }
        }
        if (Get-Module -ListAvailable -Name 'AzureAD') {
            Import-Module AzureAD
        }
        elseif (Get-Module -ListAvailable -Name 'AzureAD Preview') {
            Import-Module AzureADPreview
        }
        else {
            if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                if ($PSVersiontable.PSVersion.Major -ge 5) {
                Install-Module AzureAD -Confirm:$true
                } else {
                Write-Host "Bitte installieren Sie die Module manuell, da die PowerShell Version keine automatisierte Installation zulässt (PowerShell Version < 5)"
                }}
            else {
                Write-Host "Bitte starten Sie die PowerShell als lokaler Admin und installieren Sie das PowerShell Module AzureAD"
            }
        }
    }
    catch {
        Write-Host "Fehler bei Abruf beziehungsweise Installation der benoetigten der PowerShell Module" -ForegroundColor Red
        Write-Host $_.Exception.Message
        
    }

}


Function Connect-Services {
    [cmdletbinding()]
    param(
        [switch]$MultiFactorAuthentification
    ) 
    try {
            Write-Host "Anmeldung AzureAD"
            Connect-AzureAD
            Write-Host "Anmeldung MSolService"
            Connect-MsolService 
    }
    catch {
        Write-Host "Fehler bei Verbindungsaufbau zu Office 365 / Azure AD" 
        Write-Host $_.Exception.Message
        
    }
}

function Start-Exchange {
    param(
        [switch]$MultiFactorAuthentification
    ) 
    if (Get-Module -ListAvailable -Name 'ExchangeOnlineManagement') {
        Import-Module ExchangeOnlineManagement
        Connect-ExchangeOnline
    }else {
        Write-Host "Das Exchange Online Module ist nicht installiert. Stellen Sie bitte sicher, dass das Module ExchangeOnlineManagement installiert ist."-ForegroundColor Red
        exit
    }
}
Function Get-UnusedLicenseReport {
    param(
        [parameter(Mandatory = $true)][string]$CSVPath
    )
    try {
        $Path = $CSVPath + "\unusedlicense.csv"
        Get-MsolAccountSku | Select-Object -property AccountSkuId,ActiveUnits,ConsumedUnits, LockedOutUnits |Export-Csv -Path $Path -Append -NoTypeInformation

    }
    catch {
        Write-Host "Fehler bei Abruf der nicht genutzten Lizenzen"
        Write-Host $_.Exception.Message
    }
}
function Get-SharedMailboxLicensing {
    param(
        [parameter(Mandatory = $true)][string]$CSVPath
    )
    $CSVPath = $CSVPath + "\SharedMailboxLicensing.csv"
    $mailbox = Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails SharedMailbox | Get-MsolUser | Where-Object { $_.isLicensed -eq "TRUE" } 
    foreach ($mail in $mailbox) {
        Get-EXOMailbox $mailbox.UserPrincipalName | Export-Csv -LiteralPath $CSVPath -Append -NoTypeInformation
    }
}

Function Get-GraphReports {
    $graphUris = "https://graph.microsoft.com/v1.0/reports/getOffice365ServicesUserCounts(period='D180')",
    "https://graph.microsoft.com/v1.0/reports/getOffice365ActivationsUserDetail",
    "https://graph.microsoft.com/v1.0/reports/getOffice365ActivationsUserCounts", 
    "https://graph.microsoft.com/v1.0/reports/getMailboxUsageDetail(period='D180')",
    "https://graph.microsoft.com/v1.0/reports/getSharePointActivityUserDetail(period='D180')",
    "https://graph.microsoft.com/v1.0/reports/getOneDriveUsageAccountDetail(period='D180')",
    "https://graph.microsoft.com/v1.0/reports/getEmailActivityUserDetail(period='D180')",
    "https://graph.microsoft.com/v1.0/reports/getOneDriveActivityUserDetail(period='D180')",
    "https://graph.microsoft.com/v1.0/reports/getSkypeForBusinessActivityUserDetail(period='D180')",
    "https://graph.microsoft.com/v1.0/reports/getYammerActivityUserDetail(period='D180')",
    "https://graph.microsoft.com/v1.0/reports/getOffice365GroupsActivityDetail(period='D180')",
    "https://graph.microsoft.com/v1.0/reports/getOffice365ActiveUserDetail(period='D180')",
    "https://graph.microsoft.com/v1.0/reports/getTeamsUserActivityUserDetail(period='D180')"

    $authResult = Get-AccessToken -TenantID $TenantID -ClientID $ClientID -redirectUri $redirectUri -resourceAppIdURI $resourceAppIdURI
    try {
        if ($authResult) {
            foreach ($Uri in $graphUris) {
                $reportname = ($uri.Replace("https://graph.microsoft.com/v1.0/reports/", "").split('('))[0]
                $Path = $OutPutPath + $reportname + ".csv"
                $Header =  @{ 'Authorization' = "$($authResult.token_type) $($authResult.access_token)" }
                $Results = Invoke-RestMethod -Method Get -Headers $Header -Uri $Uri 
              
                #$Data = Invoke-MSGraphQuery -authResult $authResult -Uri $Uri -Method "Get"
                if ($Results) {
                    $Results = $Results.Remove(0, 3)        
                    $Results = ConvertFrom-Csv -InputObject $Results
                    $Results | Export-Csv -Path $Path -NoTypeInformation
                }
            }
        }
        else {
            Write-Host "Fehler bei Abruf des AccessTokens" -ForegroundColor Red
        
        }
    }
    catch {
        Write-Host "Fehler beim Export der Graph Reports"
        Write-Host $_.Exception.Message
    }
}
Function Get-LoginLogs {
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)][string]$ClientID,
        [parameter(Mandatory = $true)][string]$redirectUri,
        [parameter(Mandatory = $true)][string]$tenantId
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
    $authResult = Get-AccessToken -TenantID $tenantId -ClientID $ClientID -redirectUri $redirectUri -resourceAppIdURI $resourceAppIdURI
    foreach ($app in $Applications) {
        $filter = "`$filter=createdDateTime ge " + $PastPeriod + "T00:00:00Z and createdDateTime le " + $today + "T00:00:00Z and (appId eq '" + $app + "' or startswith(appDisplayName,'" + $app + "'))"        
        $url = "https://graph.microsoft.com/beta/auditLogs/signIns?" + $filter
        $reportname = "Audit-" + $app
        Get-AADAuditReports -clientId $ClientID -redirectUri $redirectUri -tenantId $tenantId -reportname $reportname -url $url -authResult $authResult
    }
}
Function Get-AADAuditReports {
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)][string]$clientId,
        [parameter(Mandatory = $true)][string]$redirectUri,
        [parameter(Mandatory = $true)][string]$url,
        [parameter(Mandatory = $true)][string]$reportname,
        [parameter(Mandatory = $true)][string]$tenantId,
        [parameter(Mandatory = $true)]$authResult
    )   
    $outputFile = $OutPutPath + $reportname + ".csv"
    $token = $authResult.access_token
    if ($null -eq $token) {
        Write-Host "Es konnte kein Token erstellt werden" -ForegroundColor Red
        
    }  
    $Header =  @{ 'Authorization' = "$($authResult.token_type) $($authResult.access_token)" }
    $count = 0
    $retryCount = 0
    $oneSuccessfulFetch = $False
    Do {
        Try {
            $myReport = Invoke-RestMethod -Method "Get" -Uri $url -Headers $Header
            $myReport.value  | ConvertTo-Csv -NoTypeInformation | Add-Content $outputFile
            if(-Not($myReport.value)){
                $value ='"id","createdDateTime","userDisplayName","userPrincipalName","userId","appId","appDisplayName","ipAddress","clientAppUsed","correlationId","conditionalAccessStatus","originalRequestId","isInteractive","tokenIssuerName","tokenIssuerType","processingTimeInMilliseconds","riskDetail","riskLevelAggregated","riskLevelDuringSignIn","riskState","riskEventTypes","resourceDisplayName","resourceId","authenticationMethodsUsed","mfaDetail","status","deviceDetail","location","appliedConditionalAccessPolicies","authenticationProcessingDetails","networkLocationDetails"'
                $value | Add-Content $outputFile
            }
            
            $url = ($myReport.value).'@odata.nextLink'
            $count = $count + $convertedReport.Count
            $oneSuccessfulFetch = $True
            $retryCount = 0
        }
        Catch [System.Net.WebException] {
            $statusCode = [int]$_.Exception.Response.StatusCode
            Write-Host $statusCode
            Write-Host $_.Exception.Message
            if ($statusCode -eq 401 -and $oneSuccessfulFetch) {
                
                $authResult = Get-AccessToken -ClientID $ClientID -TenantID $tenantId -redirectUri $redirectUri -resourceAppIdURI $resourceAppIdURI 
                $token = $authResult.AccessToken
                $oneSuccessfulFetch = $False
            }
            elseif ($statusCode -eq 429 -or $statusCode -eq 504 -or $statusCode -eq 503) {
                Start-Sleep -Seconds 60
                Write-Host "Prozess wird verlangsamt, um Fehler 429 zu verhindern."
            }
            elseif ($statusCode -eq 403 -or $statusCode -eq 400 -or $statusCode -eq 401) {
                Write-Host "Bitte pruefen Sie die Berechtigung der App Registrierung und des Benutzers"
                break;
            }
            else {
                if ($retryCount -lt 5) {
                    $retryCount++
                }
                else {
                    break
                }
            }
        }
        Catch {
            $exType = $_.Exception.GetType().FullName
            $exMsg = $_.Exception.Message
            Write-Output "Fehler: $_.Exception" 
            Write-Output $exType
            Write-Output $exMsg 
            if ($retryCount -lt 5) {
                $retryCount++
            }
            else {
            
                break
            }
        } 

    } until ($url -notcontains "https")
}

Function Get-AuditLogSearchData {
    $SPAuditChecks = ""
    foreach ($check in $SPAuditChecks) {
        $ReportPath = $OutPutPath + "\" +"Audit-SP-"+ $check.Split("/")[-2] + ".csv"
        [DateTime]$start = (Get-Date).AddDays(-90)
        [DateTime]$end = Get-Date
        $record = "SharePointFileOperation"
        $resultSize = 5000
        $intervalMinutes = 1440
        $retryCount = 3
        [DateTime]$currentStart = $start
        [DateTime]$currentEnd = $start
        $currentTries = 0
        while ($currentEnd -lt $end) {
            $currentEnd = $currentStart.AddMinutes($intervalMinutes)
            $currentTries = 0
            $sessionID = [DateTime]::Now.ToString().Replace('/', '_')
            $currentCount = 0
            while ($true) {
                [Array]$results = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd -RecordType $record -SessionId  $sessionID -ObjectIds $check -SessionCommand ReturnNextPreviewPage -ResultSize $resultSize
                if ($null -eq $results -or $results.Count -eq 0) {
                    #Retry if needed. This may be due to a temporary network glitch
                    if ($currentTries -lt $retryCount) {
                        $currentTries = $currentTries + 1
                        continue
                    }
                    else {
                        break
                    }
                }
                $currentTotal = $results[0].ResultCount
                if ($currentTotal -gt 5000) {
                }
                $currentCount = $currentCount + $results.Count
                $results | Export-Csv $ReportPath -NoTypeInformation -Append
                $results = ""
                if ($currentTotal -eq $results[$results.Count - 1].ResultIndex) {
                    break
                }
            }
            $currentStart = $currentEnd
        }      
    }
  if(!($SPAuditChecks)){
      $outputFile = $OutPutPath + "\" +"Audit-SP-1.csv"
      $CSVContent = '"CreationTime", "Id" ,"Operation", "OrganizationId", "RecordType", "UserKey", "UserType", "Version", "Workload", "ClientIP", "ObjectId" ,"UserId", "CorrelationId" ,"CustomUniqueId", "EventSource",  "ItemType", "ListId", "ListItemUniqueId" ,"Site", "UserAgent", "WebId", "SourceFileExtension" ,"SiteUrl", "SourceFileName", "SourceRelativeUrl"'
      $CSVContent | Out-File $outputFile
    }
}
Function Disconnect-Services {
    try {
            Disconnect-AzureAD
    }
    catch {
        Write-Host "Fehler bei Schließung der Verbindung zu den Online Services." -ForegroundColor Red
        Write-Host $_.Exception.Message
        
    }
}


function Get-AssignedPlans{
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)][string]$CSVPath
    )
    $reportname = "\assignedPlans"
    $Path = $CSVPath + $reportname + ".csv"
    #alle lizenzierten Benutzer
    Get-MsolUser -All  | Where-Object {$_.isLicensed -eq $true}   | Select-Object -Property @{name="licenses";expression={$_.licenses.accountskuid}}, UserPrincipalName | ConvertTo-Csv -NoTypeInformation | Out-File $Path -Append
}   
 
   
function UserHasLicenseAssignedDirectly
{
    Param([Microsoft.Online.Administration.User]$user, [string]$skuId)

    foreach($license in $user.Licenses)
    {   
        if ($license.AccountSkuId -ieq $skuId)
        {
              if ($license.GroupsAssigningLicense.Count -eq 0)
            {
                return $true
            }
            foreach ($assignmentSource in $license.GroupsAssigningLicense)
            {
                if ($assignmentSource -ieq $user.ObjectId)
                {
                    return $true
                }
            }
            return $false
        }
    }
    return $false
}
function UserHasLicenseAssignedFromGroup
{
    Param([Microsoft.Online.Administration.User]$user, [string]$skuId)

    foreach($license in $user.Licenses)
    {

        if ($license.AccountSkuId -ieq $skuId)
        {
            foreach ($assignmentSource in $license.GroupsAssigningLicense)
            {
                if ($assignmentSource -ine $user.ObjectId)
                {
                    return $true
                }
            }
            return $false
        }
    }
    return $false
}
function Get-LicenseAssignmentPath{
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)][string]$CSVPath
    )
    $reportname = "\LicenseAssignmentPath"
    $Path = $CSVPath + $reportname + ".csv"
    $users=Get-Msoluser -All | Where-Object { $_.islicensed -eq $true }
    $Skus = Get-MsolAccountSku 
   foreach($user in $users){
   $skus= $user.Licenses.Accountskuid
    foreach($sku in $skus){
    $obj =@()
    $obj = $user
    $UserHasLicenseAssignedDirectly = UserHasLicenseAssignedDirectly $user $sku
    $UserHasLicenseAssignedFromGroup = UserHasLicenseAssignedFromGroup $user $sku
    
    $obj | Add-Member -MemberType NoteProperty -Name "SKU" -value $sku -Force
    $obj | Add-Member -MemberType NoteProperty -Name "AssignedDirectly" -value $UserHasLicenseAssignedDirectly -Force
    $obj | Add-Member -MemberType NoteProperty -Name "AssignedFromGroup" -value $UserHasLicenseAssignedFromGroup -Force
    $obj | Select-Object -Property ObjectId, UserPrincipalName, AssignedDirectly, AssignedFromGroup, SKU | Export-Csv $path -Append -NoTypeInformation
   }
   }
   }   

   function Get-LicensingGroups{
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)][string]$CSVPath
    )
    $reportname = "\LicensingGroups"
    $Path = $CSVPath + $reportname + ".csv"
    $groups = Get-MsolGroup -All | Where-Object {$_.Licenses}
    foreach($group in $groups){
    $LicenseString= ""
    $obj=@()
    $Member =Get-MsolGroupMember -GroupObjectId $group.ObjectId -All 
    $obj = $Member
    foreach ($License in  $group.AssignedLicenses.AccountSkuId.SkuPartNumber){
        $LicenseString += $License+"; "
    }

    $obj | Add-Member -MemberType NoteProperty -Name "GroupLicense" -value $LicenseString
    $obj | Add-Member -MemberType NoteProperty -Name "GroupName" -value $group.DisplayName
    $obj | Add-Member -MemberType NoteProperty -Name "GroupId" -value $group.ObjectId
    $obj | Select-Object -Property * | Export-Csv $Path -Append -NoTypeInformation
    } 
    }   


   function Get-AdminReport{
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)][string]$CSVPath
    )
    $msolUserResults =@()
    $reportname = "\AdminReport"
    $Path = $CSVPath + $reportname + ".csv"
        $AllAdminRole = Get-MsolRole 
    foreach($Role in $AllAdminRole){
    $RoleID = $Role.ObjectID
    $Admins = Get-MsolRoleMember -TenantId $Customer.TenantId -RoleObjectId $RoleID
     foreach ($Admin in $Admins){
     if($Admin.EmailAddress){
            $user = Get-MsolUser -UserPrincipalName $Admin.EmailAddress
            #$LicenseStatus = $MsolUserDetails.IsLicensed
            $userProperties = @{
                DisplayName = $user.DisplayName
                UPN = $user.UserPrincipalName
                IsLicensed = $user.IsLicensed
                Licenses = $user.Licenses
                Adminrole = $role.Name
            }

     $msolUserResults += New-Object psobject -Property $userProperties
     }
     }
        }
$msolUserResults | Select-Object -Property * | Export-Csv -notypeinformation -Path $Path 
}

Function Invoke-CloudEconomics {
    [cmdletbinding()]
    param(
        [switch]$MultiFactorAuthentification,
        [switch]$includeExchange
    )
    ############################# Umgebungsvariablen ############################
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ErrorActionPreference = "Stop";
    $OutPutPath = "C:\CloudEconomics\"
    if (-Not (Test-Path -Path $OutPutPath)) {
        New-Item -ItemType directory -Path  $OutPutPath
    } 
    [String]$resourceAppIdURI = "https://graph.microsoft.com"
    [String]$loginurl = "https://login.microsoft.com"

   ######ä Kundendaten ###############################
   [String]$ClientID = ''                 
    [String]$TenantID = ''      
    [String]$redirectUri = 'https://localhost' 
    [String]$Secret = ''
    ##################################################

    Get-ChildItem -Path $OutPutPath -Filter *.csv | Remove-Item
    Get-ChildItem -Path $OutPutPath -Filter *.txt | Remove-Item
    Write-Host "Es werden alle alten Reports geloescht" 
    Write-Progress -Activity 'Vorbereitungen des Systems' -Status 'Crayon Cloud Economics' -PercentComplete 10 
    # Prüfung und Installation der PowerShell Module
    Test-Prerequisits 
    # Verbindung zu MS Cloud Services (Azure AD, MsOnline, Exchange Online)
    Connect-Services -MultiFactorAuthentification:$MultiFactorAuthentification
    if($includeExchange.IsPresent){
        Start-Exchange -MultiFactorAuthentification:$MultiFactorAuthentification 
        #Lizenzierte Shared Mailboxen nachschlagen
        Get-SharedMailboxLicensing -CSVPath $OutPutPath
    }
    Write-Progress -Activity 'Ungenutzte Lizenzen nachschlagen' -Status 'Crayon Cloud Economics' -PercentComplete 15 
    # Nicht genutzte Lizenzen nachschlagen
    Get-UnusedLicenseReport -CSVPath $OutPutPath
    #Write-Progress -Activity 'E5 Lizenzierung pruefen' -Status 'Crayon Cloud Economics' -PercentComplete 35
    Write-Progress -Activity 'MS Graph abfragen' -Status 'Crayon Cloud Economics' -PercentComplete 40
    #Usage Reports nachschlagen
    Get-GraphReports
    Write-Progress -Activity 'Login Logs ausgeben' -Status 'Crayon Cloud Economics' -PercentComplete 70 
    # Login Logs des Azure ADs nachschlagen
    Get-LoginLogs -ClientID $ClientID -redirectUri $redirectUri -tenantId $TenantID 
    Write-Progress -Activity 'Audit Log durchsuchen' -Status 'Crayon Cloud Economics' -PercentComplete 80 
    #Get-AuditLogSearchData
    # Unifed Logs nachschlagen 
    Write-Progress -Activity 'Alle Benutzer ausgeben' -Status 'Crayon Cloud Economics' -PercentComplete 90 
    # Alle Benutzer nachschlagen
    Get-AzureADUser -All:$true | Export-Csv -Path $OutPutPath"\AllUser.csv" -NoTypeInformation
    Get-AssignedPlans -CSVPath $OutPutPath
    Get-LicensingGroups -CSVPath $OutPutPath
    Get-LicenseAssignmentPath -CSVPath $OutPutPath
    Get-AdminReport -CSVPath $OutPutPath
    Disconnect-Services 
}

