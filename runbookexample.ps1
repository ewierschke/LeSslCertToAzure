
## need to add a cert expiry check to script in order to limit run time to only 
## execute module if cert is within defined expiry window

# Azure Runbook can execute for 20min in order to run module's  
# Set-AzureRmApplicationGateway command
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

Deploy-LeSslCertToAzure `
    -appGatewayRgName 'web-resoucegroup-rg' `
    -appGatewayName 'mydomaintocertweb-agw' `
    -appGatewayBackendPoolName 'appGatewayBackendPool' `
    -appGatewayBackendHttpSettingsName 'appGatewayBackendHttpSettings' `
    -domainToCert 'www.mydomaintocert.com' `
    -multisiteListener 'true' `
    -certPassword 'mySweetPassword123!@' `
    -azureDnsZone 'mydomaintocert.com' `
    -dnsAlias 'wwwDomainCom' `
    -azureDnsZoneResourceGroup 'web-resoucegroup-rg' `
    -registrationEmail 'ops@mydomaintocert.com'