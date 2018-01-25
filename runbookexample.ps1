
## todo-need to add a cert expiry check to runbook in order to limit runtime to 
## only execute module if cert is within defined expiry window

# Azure Runbook can execute for 20min in order to run module's  
# Set-AzureRmApplicationGateway command

# An Application Gateway and Azure DNS Zone needs to have been already created 
# along with a corresponding AppGW Backend pool, AppGW HTTP settings, and Azure 
# DNS Zone Record set A record to be entered below for the domain to cert

# Azure Automation Account needs the following modules updated/imported prior to
# executing this Runbook (typically available in the Modules gallery):
# AzureRM.Profile, AzureRM.DNS, AzureRM.Network, ACMESharp

# Azure Automation Account Variables need to be created before execution, with 
# names 'SubscriptionId' - String (unencrypted) and 
# 'CertificatePassword' - String (encrypted)

# Authentication below assumes use of Automation Account RunAs 
# account/connection

$scriptRoot = "$env:Temp"
$moduleRoot = "$scriptRoot"

if (-Not ($env:PSModulePath.Contains($moduleRoot))) {
    $env:PSModulePath = $env:PSModulePath + ";$moduleRoot"
}
Invoke-Webrequest "https://raw.githubusercontent.com/ewierschke/LeSslCertToAzure/update/Modules/Deploy-LeSslCertToAzure/Deploy-LeSslCertToAzure.psm1" -Outfile "${moduleRoot}\Deploy-LeSslCertToAzure.psm1";

$modulefile = "$moduleRoot\" + "Deploy-LeSslCertToAzure.psm1"
Import-Module -Name $modulefile -Verbose

$VerbosePreference = "Continue"
$ErrorActionPreference = 'Stop'

#Login
$connectionName = "AzureRunAsConnection"
$SubId = Get-AutomationVariable -Name 'SubscriptionId'
try
{
   # Get the connection "AzureRunAsConnection "
   $servicePrincipalConnection=Get-AutomationConnection -Name $connectionName

   "Logging in to Azure..."
   Add-AzureRmAccount `
      -ServicePrincipal `
      -TenantId $servicePrincipalConnection.TenantId `
      -ApplicationId $servicePrincipalConnection.ApplicationId `
      -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint 
   "Setting context to a specific subscription"
   Set-AzureRmContext -SubscriptionId $SubId
}
catch {
    if (!$servicePrincipalConnection)
    {
        $ErrorMessage = "Connection $connectionName not found."
        throw $ErrorMessage
    } else{
        Write-Error -Message $_.Exception
        throw $_.Exception
    }
}

$certPass = Get-AutomationVariable -Name 'CertificatePassword'
Deploy-LeSslCertToAzure `
    -appGatewayRgName 'web-resoucegroup-rg' `
    -appGatewayName 'mydomaintocertweb-agw' `
    -appGatewayBackendPoolName 'appGatewayBackendPool' `
    -appGatewayBackendHttpSettingsName 'appGatewayBackendHttpSettings' `
    -domainToCert 'www.example.com' `
    -multisiteListener 'true' `
    -certPassword $certPass `
    -azureDnsZone 'example.com' `
    -dnsAlias 'wwwExampleCom' `
    -azureDnsZoneResourceGroup 'web-resoucegroup-rg' `
    -registrationEmail 'ops@example.com'