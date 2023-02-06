

$certname = "MSGraphCert" 
$cert = New-SelfSignedCertificate -Subject "CN=$certname" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256

Export-Certificate -Cert $cert -FilePath "$certname.cer"

#Delete certificate
#Get-ChildItem -Path "Cert:\CurrentUser\My" | Where-Object {$_.Subject -Match "$certname"} | Select-Object Thumbprint, FriendlyName