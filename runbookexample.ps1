## todo-look into potential benefit of pushing private key and/or ACMEVault to 
## storage acct

# Azure Runbook can execute for 20min if requires running module's  
# Set-AzureRmApplicationGateway command

# An Application Gateway and Azure DNS Zone needs to have been already created 
# along with a corresponding AppGW Backend pool, AppGW HTTP settings, and Azure 
# DNS Zone Record set A record to be entered below for the domain/host to cert

# Azure Automation Account needs the following modules updated/imported prior to
# executing this Runbook (typically available in the Modules gallery):
# AzureRM.Profile, AzureRM.DNS, AzureRM.Network, ACMESharp

# Azure Automation Account Variables need to be created before execution, with 
# names 'SubscriptionId' - String (unencrypted) and 
# 'CertificatePassword' - String (encrypted)

# Update the block of variables as described below

# Optional parameters can be provided directly to the Deploy-LeSslCertToAzure 
# module below to use specific listener settings, routing request rule names, 
# and whether to reuse pathmap from existing routing request rule name.  
# -ApplicationGatewayHttpListenerName 
# -ApplicationGatewayRequestRoutingRuleName
# -ApplicationGatewayGetPathMapFromRequestRoutingRuleName

# Authentication below assumes use of Automation Account RunAs 
# account/connection

###update the below variables
$hosttocert = 'www.example.com'
$renewIfLessThanDays = 21
$appgwrgname = 'web-resoucegroup-rg'
$appgwname = 'mydomaintocertweb-agw'
$appgwbepoolname = 'appGatewayBackendPool'
$appgwbehttpsettingsname = 'appGatewayBackendHttpSettings'
$multisitelistener = 'true'
$azurednszone = 'example.com'
$azurednszonergname = 'web-resoucegroup-rg'
$letsencryptregemail = 'ops@example.com'
###update the above variables

#Do Not modify these variables
$certPass = Get-AutomationVariable -Name 'CertificatePassword'
$dnsalias = $hosttocert.split(".")[0]
$timeoutMilliseconds = 10000
#disabling the cert validation check. This is what makes this whole thing work with invalid certs...
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

foreach ($hostentry in $hosttocert) {
    $urltocheck = "https://" + $hostentry
    Write-Output "Checking $urltocheck"
    $req = [Net.HttpWebRequest]::Create($urltocheck)
    $req.Timeout = $timeoutMilliseconds
    $req.AllowAutoRedirect = $false
    $ErrorActionPreference = 'SilentlyContinue'
    $req.GetResponse()
    $certExpiresOnString = $req.ServicePoint.Certificate.GetExpirationDateString()
    #Write-Output "Certificate expires on (string): $certExpiresOnString"
    [datetime]$expiration = [System.DateTime]::Parse($req.ServicePoint.Certificate.GetExpirationDateString())
    #Write-Output "Certificate expires on (datetime): $expiration"
    [int]$certExpiresIn = ($expiration - $(get-date)).Days
    $certName = $req.ServicePoint.Certificate.GetName()
    $certPublicKeyString = $req.ServicePoint.Certificate.GetPublicKeyString()
    $certSerialNumber = $req.ServicePoint.Certificate.GetSerialNumberString()
    $certThumbprint = $req.ServicePoint.Certificate.GetCertHashString()
    $certEffectiveDate = $req.ServicePoint.Certificate.GetEffectiveDateString()
    $certIssuer = $req.ServicePoint.Certificate.GetIssuerName()
    if ($certExpiresIn -gt $renewIfLessThanDays) {
        Write-Output "Threshold is $renewIfLessThanDays days."
        Write-Output "Cert for site $urltocheck expires in $certExpiresIn days [on $expiration]"
        Write-Output "Not renewing certificate"
        Write-Output "Script terminating"
    }
    else {
        Write-Output "Threshold is $renewIfLessThanDays days."
        Write-Output "WARNING: Cert for site $urltocheck expires in $certExpiresIn days [on $expiration]"
        Write-Output "---"
        Write-Output "Certificate details prior to renewal:"
        Write-Output "Cert name: $certName"
        Write-Output "Cert public key: $certPublicKeyString"
        Write-Output "Cert serial number: $certSerialNumber"
        Write-Output "Cert thumbprint: $certThumbprint"
        Write-Output "Cert effective date: $certEffectiveDate"
        Write-Output "Cert issuer: $certIssuer"
        Write-Output "---"
        Write-Output "NOTICE: Attempting to renew certificate and replace on AppGw"
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $null
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
        try {
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
            if (!$servicePrincipalConnection) {
                $ErrorMessage = "Connection $connectionName not found."
                throw $ErrorMessage
            } else {
                Write-Error -Message $_.Exception
                throw $_.Exception
            }
        }

        Deploy-LeSslCertToAzure `
            -appGatewayRgName $appgwrgname `
            -appGatewayName $appgwname `
            -appGatewayBackendPoolName $appgwbepoolname `
            -appGatewayBackendHttpSettingsName $appgwbehttpsettingsname `
            -domainToCert $hosttocert `
            -multisiteListener $multisitelistener `
            -certPassword $certPass `
            -azureDnsZone $azurednszone `
            -dnsAlias $dnsalias `
            -azureDnsZoneResourceGroup $azurednszonergname `
            -registrationEmail $letsencryptregemail
    }
}