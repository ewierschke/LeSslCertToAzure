# NOTE: To install, you must run Powershell elevated 
# Install-Module AzureRM -AllowClobber
# NOTE: ACMESharp has a module that conflicts with 'Get-Certificate', -AllowClobber may allow ACMESharp to override that command.
# Install-Module ACMESharp  -AllowClobber  

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

# Login-AzureRmAccount

Deploy-LeSslCertToAzure `
    -appGatewayRgName 'web-resoucegroup-rg' `
    -appGatewayName 'mydomaintocertweb-agw' `
    -appGatewayBackendPoolName 'appGatewayBackendPool' `
    -appGatewayBackendHttpSettingsName 'appGatewayBackendHttpSettings' `
    -domainToCert 'www.example.com' `
    -multisiteListener 'true' `
    -certPassword 'mySweetPassword123!@' `
    -azureDnsZone 'example.com' `
    -dnsAlias 'wwwExampleCom' `
    -azureDnsZoneResourceGroup 'web-resoucegroup-rg' `
    -registrationEmail 'ops@example.com'