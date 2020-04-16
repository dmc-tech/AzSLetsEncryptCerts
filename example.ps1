$DebugPreference = 'continue'

$Region = '<Region>'
$FQDN = '<FQDN>'
$DNSResourceGroup = '<DNS Zone Resource>'

$Params = @{
 RegionName = $Region
 FQDN = $FQDN
 ServicePrincipal = '<Service Principal GUID>'
 ServicePrincipalSecret = '<Service Principal Secret>'
 pfxPass = 'P@ssword!'
 SubscriptionId = '<Sub Id>'
 TenantId = '<Tenant Id>'
 CertPath = 'c:\azsCerts'
}

$scriptpath = $PSScriptRoot
cd $scriptpath
import-module .\AzSLetsEncrypt.psm1


New-AzsDnsCaaRecords -ResourceGroup $DNSResourceGroup -Region $Region -FQDN $FQDN -PaaS -EventHubs
New-AzsPkiLECertificates @Params -Force -paas -EventHubs

