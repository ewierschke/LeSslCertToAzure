##############################################################################
#.SYNOPSIS
# Creates a SSL/TLS Certificate with Let's Encrypt Service 
# 
#
#.DESCRIPTION
# To maintain consistency with New-Object this cmdlet requires the -ComObject
# parameter to be provided and the TypeName parameter is not supported.
#
#.PARAMETER appGatewayRgName
# The name of an existing Azure Resource Group where the 
# Application Gateway is deployed.
#
#.PARAMETER appGatewayName
# The name of the Azure Application Gateway that has been deployed where the 
# SSL/TLS Certificate will be applied.
#
#.PARAMETER appGatewayBackendPoolName
# The name of the Backend Pool on the Application Gateway (these must
# already be setup and configured on the Application Gateway).
#
#.PARAMETER appGatewayBackendHttpSettingsName
# The name of the Backend HTTP Settings on the Application Gateway (these must
# already be setup and configured on the Application Gateway).
#
#.PARAMETER domainToCert
# The Common Name of the SSL/TLS Certificate (e.g. www.mydomain.com).
# 
#.PARAMETER multisiteListener
# True/true to create a Multi-site Listener using the domainToCert as hostname.
# 
#.PARAMETER certPassword
# The password used to encrypt the PKCS#12 PFX Certificate file.
#
#.PARAMETER azureDnsZone
# The name of the Azure DNS Zone Resource that has the authority to answer for
# the domain (e.g. if SSL/TLS Common name is www.mydomain.com, the DNS Zone 
# would be for mydomain.com).
#
#.PARAMETER azureDnsZoneResourceGroup
# The name of an existing Azure Resource Group where the 
# DNS Zone Resource, specified by azureDnsZone, is deployed.
#
#.PARAMETER dnsAlias
# The internal Alias used by ACMESharp to track the certificate, metadata, 
# and registration status.
#
#.PARAMETER registrationEmail
# The email address registred with Let's Encrypt when registering the 
# SSL/TLS Cert.
#
#.PARAMETER (optional) ApplicationGatewayHttpListenerName
# The name of the Http Listener you want to use/reuse 
#
#.PARAMETER (optional) ApplicationGatewayRequestRoutingRuleName
# The name of the Request Routing Rule you want to use
#
#.PARAMETER (optional) ApplicationGatewayGetPathMapFromRequestRoutingRuleName
# For Path Based Routing Rule, the name of the Request Routing Rule from which 
# you want to get the pathmap
#
#.EXAMPLE
# Deploy-LeSslCertToAzure `
#                -appGatewayRgName 'web-resoucegroup-rg' `
#                -appGatewayName 'mydomaintocertweb-agw' `
#                -appGatewayBackendPoolName 'appGatewayBackendPool' `
#                -appGatewayBackendHttpSettingsName 'appGatewayBackendHttpSettings' `
#                -domainToCert 'www.mydomaintocert.com' `
#                -multisiteListener 'true' `
#                -certPassword 'mySweetPassword123!@' `
#                -azureDnsZone 'mydomaintocert.com' `
#                -azureDnsZoneResourceGroup 'web-resoucegroup-rg' `
#                -dnsAlias 'wwwDomainCom' `
#                -registrationEmail 'ops@mydomaintocert.com'
##############################################################################
Function Deploy-LeSslCertToAzure() {
    Param(
        [Parameter(Mandatory=$true)]
        $appGatewayRgName,
        [Parameter(Mandatory=$true)]
        $appGatewayName,
        [Parameter(Mandatory=$true)]
        $appGatewayBackendPoolName,
        [Parameter(Mandatory=$true)]
        $appGatewayBackendHttpSettingsName,
        [Parameter(Mandatory=$true)]
        $domainToCert,
        [Parameter(Mandatory=$true)]
        [ValidateSet("true","True","false","False")]
        $multisiteListener,
        [Parameter(Mandatory=$true)]
        $certPassword,
        [Parameter(Mandatory=$true)]
        $azureDnsZone,
        [Parameter(Mandatory=$true)]
        $azureDnsZoneResourceGroup,
        [Parameter(Mandatory=$true)]
        $dnsAlias,
        [Parameter(Mandatory=$true)]
        $registrationEmail,
        [Parameter(Mandatory=$false)]
        $ApplicationGatewayHttpListenerName = 'listener-basic',
        [Parameter(Mandatory=$false)]
        $ApplicationGatewayRequestRoutingRuleName = 'rule-basic',
        [Parameter(Mandatory=$false)]
        $ApplicationGatewayGetPathMapFromRequestRoutingRuleName
    )
    Set-StrictMode -Version 3
    ########################
    # Initialize Variables
    ########################
    Import-Module ACMESharp
  
    $VerbosePreference = "Continue"
    $ErrorActionPreference = 'Stop'
 
    $dnsCertAlias = $dnsAlias + "cert"
 
    # Create the Host name to put the _acme-challenge. prefix on.
    # if certing www.mydomain.com, would create TXT record for _acme-challenge.www.mydomain.com.
 
    $acmeValidationDnsHostName = '_acme-challenge.'  + $domainToCert.Replace(".$azureDnsZone",'')
  
    $appGatewayFrontEndHttpsPortName = 'appGatewayFrontendHttpsPort'
    $appGatewayHttpsPort = 443
    $scriptRoot = "$env:Temp"
    $boolmultisiteListener = [System.Convert]::ToBoolean("$multisiteListener")
    $hostnametoCert = $domainToCert.split(".")[0]
    $fpHttpsPort = $null

    if (($boolmultisiteListener) -and ($ApplicationGatewayHttpListenerName -eq 'listener-basic')) {
        $appGwHttpsListenerName = "${hostnametoCert}-multi-site"
    } elseif ((-Not ($boolmultisiteListener)) -and ($ApplicationGatewayHttpListenerName -eq 'listener-basic')) {
        $appGwHttpsListenerName = "${hostnametoCert}-basic"
    } else {
        $appGwHttpsListenerName = "${ApplicationGatewayHttpListenerName}"
    }

    if ($ApplicationGatewayRequestRoutingRuleName -eq 'rule-basic') {
        $appGatewayHttpsRuleName = "${hostnametoCert}-basic"
    } else {
        $appGatewayHttpsRuleName = "${ApplicationGatewayRequestRoutingRuleName}"
    }
    ###############################################################
    ###############################################################
    ###############################################################
    # location to write PFX certificate to deploy to Gateway
    $signedSslCertificate = "$scriptRoot\$dnsAlias.pfx"
 
    ###
    # STAGE ONE - Setup ACME Vault, Validation Domain OwnerShip, and submit, sign and save SSL/TLS Certificate.
    ###
    # Check to see if ACME Vault exists, if not create it
    if ((Get-ACMEVault) -eq $null) {
        Write-Verbose "ACME Cert Vault doesn't exist. Initializing..."
        Initialize-ACMEVault
    }
  
    # Script didn't handle -ErrorAction SilentlyContinue properly, put in try/catch block
    try {
        Write-Verbose "ACME Cert Vault: Getting Registration..."
        # try and get registration
        Get-ACMERegistration
    } catch {
        Write-Verbose "ACME Cert Vault: Not registered. Performing registration..."
        # Vault doesn't exist, create it.
        New-ACMERegistration -Contacts "mailto:$registrationEmail" -AcceptTos
    }
  
    # Had to use try/catch since script didn't handle -ErrorAction SilentlyContinue properly
    try {
        # See if Identifier is already registered
        Write-Verbose "Checking if ACME Identifier $dnsAlias already exists."
        (Get-ACMEIdentifier -IdentifierRef $dnsAlias)
        $dnsTxtValue = ((Get-ACMEIdentifier -IdentifierRef $dnsAlias).Challenges | Where-Object {$_.Type -eq "dns-01"}).Challenge.RecordValue 
        Write-Verbose "It exists, DNS TXT value requested is '$dnsTxtValue.'"
    } catch {
        # No Identifier, create one.
        Write-Verbose "It does not exist. Creating a new Identifier alias $dnsAlias for $domainToCert."
        New-ACMEIdentifier -Dns $domainToCert -Alias $dnsAlias
        Write-Verbose "Requesting ACME DNS TXT Record Challenge..."
        $authorizationState = Complete-ACMEChallenge $dnsAlias -ChallengeType dns-01 -Handler manual
        $dnsTxtValue = ($authorizationState.Challenges | Where-Object {$_.Type -eq "dns-01"}).Challenge.RecordValue
        Write-Verbose "Success, retrieved value $dnsTxtValue"
    }
  
    if ([string]::IsNullOrEmpty($dnsTxtValue)) {
        throw "Could not determine Proper TXT Resource Record (RR) value from ACME client."
    }
  
    # Attempt to retrieve an existing DNS record for this domain, if it exists
    Write-Verbose "Checking to see if $acmeValidationDnsHostName DNS txt record in Zone $azureDnsZone in Resource Group $azureDnsZoneResourceGroup already exists."
    $dnsRecordSet = Get-AzureRmDnsRecordSet `
                                    -Name $acmeValidationDnsHostName `
                                    -ZoneName $azureDnsZone `
                                    -ResourceGroupName $azureDnsZoneResourceGroup `
                                    -RecordType TXT `
                                    -ErrorAction SilentlyContinue
    if ($dnsRecordSet -eq $null) {
        Write-Verbose "Record does not exist for this TXT record. Creating..."
 
        $dnsRecordSet = New-AzureRmDnsRecordSet `
                    -Name $acmeValidationDnsHostName `
                    -RecordType 'TXT' `
                    -ZoneName $azureDnsZone `
                    -ResourceGroupName $azureDnsZoneResourceGroup `
                    -Ttl 60 `
                    -DnsRecords @(New-AzureRmDnsRecordConfig -Value $dnsTxtValue)
    } else {
        Write-Verbose "Record exists. Performing update."
        if ($dnsRecordSet.Records.Count -eq 0) {
            # No record at all, create a new one.
            $txtRecord = New-AzureRmDnsRecordConfig -Value $dnsTxtValue
            # Add Record set.
            $dnsRecordSet.Records.Add($txtRecord)
        } else {
            # Found a record, but need to update it.
            $dnsRecordSet.Records[0].Value = $dnsTxtValue
        }
    }
     
    Write-Verbose "Saving DNS TXT record for let's encrypt challenge."
    Set-AzureRmDnsRecordSet -RecordSet $dnsRecordSet
  
    #give it some time to create the record so it's avail when we submit to lets encrypt.
    Start-Sleep -s 10
  
    # submit for processing
    Write-Verbose "Submitting request for DNS challenge."
    Submit-ACMEChallenge $dnsAlias -ChallengeType dns-01
  
    [string]$status = ((Update-ACMEIdentifier `
                                    $dnsAlias `
                                    -ChallengeType dns-01 `
                       ).Challenges | Where-Object {$_.Type -eq "dns-01"}).Status
  
    # Setup a timeout to wait for the Main stack to be ready / online to retrieve the Output params
    # if it's not ready right away. Typically this happens immediately.
    $timeout = new-timespan -Minutes 5
    $sw = [diagnostics.stopwatch]::StartNew()
  
    # loop until valid or 5 minute timeout is reached.
    while (-Not $status.Equals('valid')) {
        Write-Verbose "Current Status is $status."
        # check to see if timeout should occur
        if ($sw.elapsed -ge $timeout) {break;}
  
        Write-Verbose "Waiting for certificate to be valid."
        start-sleep -seconds 5
        $status = ((Update-ACMEIdentifier `
                            $dnsAlias `
                            -ChallengeType dns-01 `
                   ).Challenges | Where-Object {$_.Type -eq "dns-01"}).Status
    }
  
    if (-Not $status.Equals('valid')) {
        Write-Error "Not valid after 5 min. Status is $status."
        return
    } else {
        Write-Verbose "Cert is Valid! Deploying.."
  
        # Create a new certificate to get signed
         
        Write-Verbose "Checking to see if certificate $dnsCertAlias was already Created."
        # check to see if certificate was already created.
        $dnsCertCreated = $null
        try{
            $dnsCertCreated = (Get-ACMECertificate | Where-Object {$_.Alias -eq $dnsCertAlias})
        }
        catch{}
        if ($dnsCertCreated -eq $null) {
            Write-Verbose "Creating new certificate $dnsCertAlias to sign."
            New-ACMECertificate $dnsAlias -Generate -Alias $dnsCertAlias
            Write-Verbose "Submitting $dnsCertAlias certificate for signature."
            Submit-ACMECertificate $dnsCertAlias
        }
         
        Write-Verbose "Updating ACME Vault by storing certificate $dnsCertAlias."
        Update-ACMECertificate $dnsCertAlias
  
        Write-Verbose "Retrieving SSL Certificate in PKCS#12 format with full cert chain."
        # Retrieve the signed cert with Private key including chain (intermediate CA must be installed above for this to work)
        # and store it in the Pkcs#12 format.
        Get-ACMECertificate $dnsCertAlias -ExportPkcs12 $signedSslCertificate -CertificatePassword $certPassword -Overwrite
 
        ###
        # STAGE TWO - DEPLOY PFX to Azure Application Gateway
        ###
 
 
        Write-Verbose "Deploying Certificate to the Application Gateway $appGatewayName in resource group $appGatewayRgName."
        # Retrieve app gateway
        $appGateway = Get-AzureRmApplicationGateway -ResourceGroupName $appGatewayRgName -Name $appGatewayName
  
        # Create a new SSL port and add it to the front ends ports
        Write-Verbose "Creating SSL FrontEnd Port for SSL/TLS on TCP 443."
        $currentfrontendports = Get-AzureRmApplicationGatewayFrontendPort -ApplicationGateway $appGateway
        foreach ($n in $currentfrontendports) {
            if ($n.Port -eq 443) {
                $fpHttpsPort = $n 
            }
        }
        if (!$fpHttpsPort) {
            Remove-AzureRmApplicationGatewayFrontendPort -ApplicationGateway $appGateway -Name "appGatewayFrontendPort" -ErrorAction SilentlyContinue
            Add-AzureRmApplicationGatewayFrontendPort -ApplicationGateway $appGateway -Name $appGatewayFrontEndHttpsPortName -Port $appGatewayHttpsPort
            $fpHttpsPort = Get-AzureRmApplicationGatewayFrontendPort -name $appGatewayFrontEndHttpsPortName -ApplicationGateway $appGateway
        }


        # Load cert
        Write-Verbose "Adding SSL/TLS Certificate: $signedSslCertificate."
        $securecertPassword = ConvertTo-SecureString -String "$certPassword" -AsPlainText -Force
        #try-catch to replace existing cert with matching name
        try {
            $cert = Get-AzureRmApplicationGatewaySslCertificate -ApplicationGateway $appGateway -Name $dnsCertAlias
            Set-AzureRmApplicationGatewaySslCertificate -ApplicationGateway $appGateway -Name $dnsCertAlias -CertificateFile $signedSslCertificate -Password $securecertPassword
        } catch {
            Add-AzureRmApplicationGatewaySslCertificate -ApplicationGateway $appGateway -Name $dnsCertAlias -CertificateFile $signedSslCertificate -Password $securecertPassword
        }
        #Add-AzureRmApplicationGatewaySslCertificate -ApplicationGateway $appGateway -Name $dnsCertAlias -CertificateFile $signedSslCertificate -Password $securecertPassword
        $cert = Get-AzureRmApplicationGatewaySslCertificate -ApplicationGateway $appGateway -Name $dnsCertAlias
        # Get frontEndIP
        $fipconfig = Get-AzureRmApplicationGatewayFrontendIPConfig -ApplicationGateway $appGateway
        
        # Remove old Listeners and Rules
        Remove-AzureRmApplicationGatewayHttpListener -ApplicationGateway $appGateway -Name "appGatewayHttpListener" -ErrorAction SilentlyContinue
        Remove-AzureRmApplicationGatewayHttpListener -ApplicationGateway $appGateway -Name $appGwHttpsListenerName -ErrorAction SilentlyContinue
        Remove-AzureRmApplicationGatewayRequestRoutingRule -ApplicationGateway $appGateway -Name "rule1" -ErrorAction SilentlyContinue
        $getPathMapFromRoutingRule = Get-AzureRmApplicationGatewayRequestRoutingRule -ApplicationGateway $appGateway -Name $ApplicationGatewayGetPathMapFromRequestRoutingRuleName -ErrorAction SilentlyContinue
        if (!$getPathMapFromRoutingRule) {
            Write-Verbose "ERROR Routing Rule from which to get pathmap doesn't exist"
        } elseif ($getPathMapFromRoutingRule.RuleType -eq "PathBasedRouting") {
            $getPathMapFrom = "true"
        } elseif ($getPathMapFromRoutingRule.RuleType -eq $null) {
            Write-Verbose "ERROR Routing Rule from which to get pathmap doesn't contain a pathmap, is basic?"
        } else {
            $getPathMapFrom = "false"
        }
        $oldappGatewayHttpsRule = Get-AzureRmApplicationGatewayRequestRoutingRule -ApplicationGateway $appGateway -Name $appGatewayHttpsRuleName -ErrorAction SilentlyContinue
        if (!$oldappGatewayHttpsRule) {
            $createnewrule = "true"
            if ($getPathMapFromRoutingRule) {
                $oldwaspathbased = "true"
            } else {
                $oldwaspathbased = "false"
            }
        } elseif ($oldappGatewayHttpsRule.RuleType -eq "PathBasedRouting") {
            $oldwaspathbased = "true"
            $createnewrule = "false"
        } elseif ($oldappGatewayHttpsRule.RuleType -eq "Basic") {
            $oldwaspathbased = "false"
            $createnewrule = "false"
        } else {
            $oldwaspathbased = "false"
        }

        if (!$oldappGatewayHttpsRule) {
            $oldhasredirect = "false"
        } elseif ($oldappGatewayHttpsRule.RedirectConfigurationText -eq 'null') {
            $oldhasredirect = "false"
        } else {
            $oldhasredirect = "true"
        }
        Remove-AzureRmApplicationGatewayRequestRoutingRule -ApplicationGateway $appGateway -Name $appGatewayHttpsRuleName -ErrorAction SilentlyContinue
        #Remove all rules from listener being removed to avoid two rules on listener
        $rules = Get-AzureRmApplicationGatewayRequestRoutingRule -ApplicationGateway $appGateway
        foreach ($rule in $rules) {
            if ($rule.HttpListenerText.split('/')[10].split('"')[0] -eq $appGwHttpsListenerName) {
                Remove-AzureRmApplicationGatewayRequestRoutingRule -ApplicationGateway $appGateway -Name $rule.Name
            }
        }
        
        # Create a new Listener using the new https port
        Write-Verbose "Creating new HTTPS Listener..."
        if ($boolmultisiteListener) {
            Add-AzureRmApplicationGatewayHttpListener -ApplicationGateway $appGateway -Name $appGwHttpsListenerName -Protocol Https -FrontendIPConfiguration $fipconfig -FrontendPort $fpHttpsPort -HostName $domainToCert -RequireServerNameIndication true -SslCertificate $cert
        } 
        else { 
            Add-AzureRmApplicationGatewayHttpListener -ApplicationGateway $appGateway -Name $appGwHttpsListenerName -Protocol Https -FrontendIPConfiguration $fipconfig -FrontendPort $fpHttpsPort -SslCertificate $cert
        }
        $listener = Get-AzureRmApplicationGatewayHttpListener -ApplicationGateway $appGateway -Name $appGwHttpsListenerName
  
        # Get ref to backend pool
        $backendPool = Get-AzureRmApplicationGatewayBackendAddressPool -ApplicationGateway $appGateway -Name $appGatewayBackendPoolName
  
        # Get backend Pool
        $poolSetting = Get-AzureRmApplicationGatewayBackendHttpSettings -ApplicationGateway $appGateway -name $appGatewayBackendHttpSettingsName
  
        #Create request routing rule
        Write-Verbose "Adding new Routing Rule for new HTTPS Listener..."
        Get-AzureRmApplicationGatewayRequestRoutingRule -ApplicationGateway $appGateway
        #new or existing basic rule
        if ($oldwaspathbased -eq "false") {
            if ($oldhasredirect -ne "false") {
                #basic rule with redirect configuration
                $oldredirectname = $oldappGatewayHttpsRule.RedirectConfigurationText.split('/')[10].split('"')[0]
                $oldredirect = Get-AzureRmApplicationGatewayRedirectConfiguration -ApplicationGateway $appGateway -Name $oldredirectname
                Add-AzureRmApplicationGatewayRequestRoutingRule -ApplicationGateway $appGateway -Name $appGatewayHttpsRuleName -RuleType Basic -BackendHttpSettings $poolSetting -HttpListener $listener -BackendAddressPool $backendPool -RedirectConfiguration $oldredirect
            } else {
                #basic rule without redirect configuration
                Add-AzureRmApplicationGatewayRequestRoutingRule -ApplicationGateway $appGateway -Name $appGatewayHttpsRuleName -RuleType Basic -BackendHttpSettings $poolSetting -HttpListener $listener -BackendAddressPool $backendPool
            }
        #existing path based rule
        } elseif (($oldwaspathbased -eq "true") -And ($createnewrule -eq "false")) {
            #rulename not provided, getpathmapfrom provided
            } if (($appGatewayHttpsRuleName -eq "${hostnametoCert}-basic") -And ($ApplicationGatewayGetPathMapFromRequestRoutingRuleName)) {
                if ($oldhasredirect -ne "false") {
                    #path-based rule with redirect configuration
                    $appGatewayHttpsRuleName = "${hostnametoCert}-pathbased"
                    $oldredirectname = $oldappGatewayHttpsRule.RedirectConfigurationText.split('/')[10].split('"')[0]
                    $oldredirect = Get-AzureRmApplicationGatewayRedirectConfiguration -ApplicationGateway $appGateway -Name $oldredirectname
                    $getpathmapname = $getPathMapFromRoutingRule.UrlPathMapText.split('/')[10].split('"')[0]
                    $getpathmap = Get-AzureRmApplicationGatewayUrlPathMapConfig -ApplicationGateway $appGateway -Name $getpathmapname
                    Add-AzureRmApplicationGatewayRequestRoutingRule -ApplicationGateway $appGateway -Name $appGatewayHttpsRuleName -RuleType PathBasedRouting -HttpListener $listener -UrlPathMap $getpathmap -RedirectConfiguration $oldredirect
                } else {
                    #path-based rule without redirect configuration
                    $appGatewayHttpsRuleName = "${hostnametoCert}-pathbased"
                    $getpathmapname = $getPathMapFromRoutingRule.UrlPathMapText.split('/')[10].split('"')[0]
                    $getpathmap = Get-AzureRmApplicationGatewayUrlPathMapConfig -ApplicationGateway $appGateway -Name $getpathmapname
                    Add-AzureRmApplicationGatewayRequestRoutingRule -ApplicationGateway $appGateway -Name $appGatewayHttpsRuleName -RuleType PathBasedRouting -HttpListener $listener -UrlPathMap $oldpathmap
                }
            #rulename provided, getpathmapfrom not provided
            } elseif (($appGatewayHttpsRuleName -ne "${hostnametoCert}-basic") -And (!$ApplicationGatewayGetPathMapFromRequestRoutingRuleName)) {
                if ($oldhasredirect -ne "false") {
                    #path-based rule with redirect configuration
                    $oldredirectname = $oldappGatewayHttpsRule.RedirectConfigurationText.split('/')[10].split('"')[0]
                    $oldredirect = Get-AzureRmApplicationGatewayRedirectConfiguration -ApplicationGateway $appGateway -Name $oldredirectname
                    $oldpathmapname = $oldappGatewayHttpsRule.UrlPathMapText.split('/')[10].split('"')[0]
                    $oldpathmap = Get-AzureRmApplicationGatewayUrlPathMapConfig -ApplicationGateway $appGateway -Name $oldpathmapname
                    Add-AzureRmApplicationGatewayRequestRoutingRule -ApplicationGateway $appGateway -Name $appGatewayHttpsRuleName -RuleType PathBasedRouting -HttpListener $listener -UrlPathMap $oldpathmap -RedirectConfiguration $oldredirect
                } else {
                    #path-based rule without redirect configuration
                    $oldpathmapname = $oldappGatewayHttpsRule.UrlPathMapText.split('/')[10].split('"')[0]
                    $oldpathmap = Get-AzureRmApplicationGatewayUrlPathMapConfig -ApplicationGateway $appGateway -Name $oldpathmapname
                    Add-AzureRmApplicationGatewayRequestRoutingRule -ApplicationGateway $appGateway -Name $appGatewayHttpsRuleName -RuleType PathBasedRouting -HttpListener $listener -UrlPathMap $oldpathmap
                }
            #rulename provided, getpathmapfrom provided
            } elseif (($appGatewayHttpsRuleName -ne "${hostnametoCert}-basic") -And ($ApplicationGatewayGetPathMapFromRequestRoutingRuleName)) {
                if ($oldhasredirect -ne "false") {
                    #path-based rule with redirect configuration
                    $oldredirectname = $oldappGatewayHttpsRule.RedirectConfigurationText.split('/')[10].split('"')[0]
                    $oldredirect = Get-AzureRmApplicationGatewayRedirectConfiguration -ApplicationGateway $appGateway -Name $oldredirectname
                    $getpathmapname = $getPathMapFromRoutingRule.UrlPathMapText.split('/')[10].split('"')[0]
                    $getpathmap = Get-AzureRmApplicationGatewayUrlPathMapConfig -ApplicationGateway $appGateway -Name $getpathmapname
                    Add-AzureRmApplicationGatewayRequestRoutingRule -ApplicationGateway $appGateway -Name $appGatewayHttpsRuleName -RuleType PathBasedRouting -HttpListener $listener -UrlPathMap $getpathmap -RedirectConfiguration $oldredirect
                } else {
                    #path-based rule without redirect configuration
                    $getpathmapname = $getPathMapFromRoutingRule.UrlPathMapText.split('/')[10].split('"')[0]
                    $getpathmap = Get-AzureRmApplicationGatewayUrlPathMapConfig -ApplicationGateway $appGateway -Name $getpathmapname
                    Add-AzureRmApplicationGatewayRequestRoutingRule -ApplicationGateway $appGateway -Name $appGatewayHttpsRuleName -RuleType PathBasedRouting -HttpListener $listener -UrlPathMap $getpathmap
                }
            } else {
                Write-Verbose "Edge Case - should not see this - rulename and pathmap parameter error"
            }
        # create new path based rule
        } elseif ($createnewrule -eq "true") {
            if (($appGatewayHttpsRuleName -ne "${hostnametoCert}-basic") -And (!$ApplicationGatewayGetPathMapFromRequestRoutingRuleName)) {
                Write-Verbose "Can't create new path rule with this script"
            } elseif (($appGatewayHttpsRuleName -eq "${hostnametoCert}-basic") -And ($ApplicationGatewayGetPathMapFromRequestRoutingRuleName)) {
                $getpathmapname = $getPathMapFromRoutingRule.UrlPathMapText.split('/')[10].split('"')[0]
                $getpathmap = Get-AzureRmApplicationGatewayUrlPathMapConfig -ApplicationGateway $appGateway -Name $getpathmapname
                Add-AzureRmApplicationGatewayRequestRoutingRule -ApplicationGateway $appGateway -Name $appGatewayHttpsRuleName -RuleType PathBasedRouting -HttpListener $listener -UrlPathMap $getpathmap
            } elseif (($appGatewayHttpsRuleName -ne "${hostnametoCert}-basic") -And (!$ApplicationGatewayGetPathMapFromRequestRoutingRuleName)) {
                Write-Verbose "Can't create new path rule with this script"
            } elseif (($appGatewayHttpsRuleName -ne "${hostnametoCert}-basic") -And ($ApplicationGatewayGetPathMapFromRequestRoutingRuleName)) {
                $getpathmapname = $getPathMapFromRoutingRule.UrlPathMapText.split('/')[10].split('"')[0]
                $getpathmap = Get-AzureRmApplicationGatewayUrlPathMapConfig -ApplicationGateway $appGateway -Name $getpathmapname
                Add-AzureRmApplicationGatewayRequestRoutingRule -ApplicationGateway $appGateway -Name $appGatewayHttpsRuleName -RuleType PathBasedRouting -HttpListener $listener -UrlPathMap $getpathmap
            } else {
                Write-Verbose "Not Covered"
            }
        } else {
            Write-Verbose "Edge Case - should not see this - should only be either path based or basic - error"
        }

        Write-Verbose "Saving changes..."
        # Commit the changes to Azure
        Set-AzureRmApplicationGateway -ApplicationGateway $appGateway
    }
}