# M365 Usage Reports

This script uses Microsoft [Graph PowerShell](https://learn.microsoft.com/en-us/powershell/microsoftgraph/get-started) and [Exhange Online PowerShell](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell) modules to generate M365 usage reports.

## Display Concealed Information

In order to generate reports the below settings need to be enabled. If you do not allow the report to display usernames, groups and site you the script may not function correctly and the reports will not display the correct data.

- Navigate to [https://admin.microsoft.com](https://admin.microsoft.com/)
- Click on Setting -> Org Settings -> Reports
- Ensure that that the following options are checked:
  - Display concealed user, groups, and site names in all reports
  - Make report data available to Microsoft 365 usage analytics for Power BI
- Save changes.
  
![Reports](img/reports.png)

## Authentication

Microsoft Graph PowerShell supports two types of authentication, ___Delegated___ and ___App Only___. With ___Delegated Authentication___ you will be prompted to log in with a valid user account and password each time the script is executed. With ___App Only___ auhentication, authentication is validated against an ___Azure App Registration and Certificate___

To enable ___Delegated Authentication___, set ```"BasicAuth":"True"``` in the ___Config/config.json___ file.

___Please Note!___ Delegated Authentication is not the recommended authentication method, however if you use delegated authentication you need to ensure the user has sufficient permissions to execute the scripts.

To use ___App only Authentication___ set ```"BasicAuth":"False"``` in the ___Config/config.json___ file and follow the below steps for the ___Certificate___ and ___App Registration___

## Certificate

In order to complete the below step for App Registration you will require a certificate from a certificate authority or a self signed certificate. If you do not have a certificate signed by a certificate authority you can create a self signed certificate as described below.

- From the project directory execute the PowerShell script called self_signed.ps1 , this will generate a self signed certificate.

For more information regarding certificates, view the official documentation on the [Microsoft Site](https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-create-self-signed-certificate)

## App Registration

To Authenticate with your tenant an Azure AD App Registration is required, follow the belwo steps to enable App Registration for your tenant:

- Navigate to [Azure Active Directory](https://aad.portal.azure.com/)
- From the portal Select Azure Active Directory and then select App registration
  ![App Registration](img/app-reg.png)
- Select New registration. On the Register an application page, set the values as follows
  - Add a name
  - Set Supported account types to Accounts in this organizational directory only.
  - Leave Redirect URI blank.
- Click on Register
- Once the app has been registered, save the ApplicationId and TenantId to the respective fields of the ___config.json___ file
- Select API Permissions under Manage.
  - Click Add a permission and select Microsoft Graph, then Application Permissions. Add User.Read.All, Group.Read.All, Directory.Read.All and Reports.Read.All, AuditLog.Read.All, then select Add permissions.
  - Click Add a permission and select "APIs My organisation uses" and Search for "Office 365 Exchange Online". Select Application Permissions and add Exchange.ManageAsApp
- In the Configured permissions, remove the delegated User.Read permission under Microsoft Graph by selecting the ... to the right of the permission and selecting Remove permission. Select Yes, remove to confirm.
- Select the Grant admin consent for... button, then select Yes to grant admin consent for the configured application permissions. The Status column in the Configured permissions table changes to Granted for ....
- Select Certificates & secrets under Manage. Select the Upload certificate button. Browse to your certificate's public key file and select Add.
  - Copy the certificate Thumbprint and save it to the ___config.json___  file  
  - ___Please Note___: The certificate will have an experation date, if the certificate expires an new certificate will be required

## Assign Azure AD roles to the application

In the Azure AD Portal, under Roles and Administration add the following roles to the App Registration that was created in the previous step:

- Exchange administrator
- Compliance Administrator

## Install the Microsoft Graph PowerShell SDK

For updated information, review the [official documentation](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation)

Run the below comand as an admin user:

``` PowerShell
Install-Module Microsoft.Graph -Scope AllUsers
```

To verify the modules were installed run:

```PowerShell
Get-InstalledModule Microsoft.Graph
```

Run the below command to validate the installation:

```PowerShell
Get-InstalledModule Microsoft.Graph
```

## Exchange Online PowerShell

For updated information, review the [official documentation](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps)

Run the below commands with admin permissions to install Echange PowerShell module.

```Install-Module -Name ExchangeOnlineManagement```

## Configuration

Script configuration definitions are stored in the ___config.json___ file in the Config directory. Please ensure your AppId, TenantId and CertificateThumprint are added to the config.json file as per the below exammple

```json
{
    "Tenant": {
        "AppId": "YOUR_APP_ID",
        "TenantId": "YOUR_TENANT_ID",
        "CertificateThumbprint" : "YOUR_CERTIFICATETHUMBPRINT" ,
        "TenantDnsName":"YOUR_DNS_NAME.onmicrosoft.com"
    },
    "BasicAuth":"False"
}
```

## Generated Reports

Reports generated by the script will be stored in the Output folder. Each time you run the script the files in the folder will be purged so ensure you copy required files before running the script.

## Executing the script

To execut the script navigate to the folder where the script is stored and run the below command:

```PowerShell
.\usage_report.ps1
```

### Folder Structure

- `Config/config.json` contains all configuration to run the scrip
- Executing the script will create a folder called Output and store all generated reports.
- MSGraphCert.cer is the self signed certificate generated by the script ```self_signed.ps1``` . The certificate is required for authentication.
- The script ```usage_report.ps1``` is used to generate the required reports.

```md
📦 
├─ Config
│  └─ config.json
├─ img/
├─ .gitignore
├─ Output
│  ├─ getOffice365ServicesUserCounts.csv
│  ├─ getOffice365ServicesUserCounts.csv
│  ├─ getOffice365ActivationsUserCounts.csv
│  ├─ getMailboxUsageDetail.csv
│  ├─ getSharePointActivityUserDetail.csv
│  ├─ getOneDriveUsageAccountDetail.csv
│  ├─ getEmailActivityUserDetail.csv
│  ├─ getOneDriveActivityUserDetail.csv
│  ├─ getSkypeForBusinessActivityUserDetail.csv 
│  ├─ getYammerActivityUserDetail.csv
│  ├─ getOffice365GroupsActivityDetail.csv
│  ├─ getOffice365ActiveUserDetail.csv
│  ├─ getTeamsUserActivityUserDetail.csv
│  └─ unusedlicense.csv
├─ MSGraphCert.cer
├─ self_signed.ps1
└─ usage_report.ps1
```
