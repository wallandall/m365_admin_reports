# M365 Usage Reports

## Display Concealed Information

- Navigate to [https://admin.microsoft.com](https://admin.microsoft.com/)
- Click on Setting -> Org Settings -> Reports
- Ensure that that the following options are checked:
  - Display concealed user, groups, and site names ina ll reports
  - Make report data available to Microsoft 365 usage analytics for Power BI
- Save changes.
  
![Reports](img/reports.png)

## Install the Microsoft Graph PowerShell SDK

For updated information, review the [official documentation](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation)

Run the below comand as an admin user:

``` PowerShell
Install-Module Microsoft.Graph -Scope AllUsers
```

