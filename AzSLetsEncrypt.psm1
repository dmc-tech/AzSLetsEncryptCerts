# v.04
# uses AzureRM. Uses new readinessChecker.  Readiness checker needs AzureRm as is written for Azure Stack

#Requires -RunAsAdministrator
#Requires -Modules @{'ModuleName'='Posh-Acme';'ModuleVersion'='3.5.0'},@{'ModuleName'='AzureRM.Dns';'ModuleVersion'='5.1.0'} ,@{'ModuleName'='Microsoft.AzureStack.ReadinessChecker';'ModuleVersion'='1.2002.1111.69'}

#Requires -RunAsAdministrator
#Requires -Modules @{'ModuleName'='Posh-Acme';'ModuleVersion'='3.5.0'},@{'ModuleName'='Az.Dns';'ModuleVersion'='1.1.2'} ,@{'ModuleName'='Microsoft.AzureStack.ReadinessChecker';'ModuleVersion'='1.2002.1111.69'}
function new-AzsPACert ($AzsCert, [switch]$LegacyCert, $Path, $azParams, $Force) {
    foreach ($Key in $AzsCert.Keys) {
        if (-not (Test-Path -Path "$Path\$Key")) {
            New-Item -ItemType Directory -Path "$Path\$Key"
        }
        $Cert = ($AzsCert[$Key]).Replace("""", "'")
        $maindomain = $cert.Split(',')
        $existCerts = Get-ChildItem  Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*$($maindomain[0])"}
        If ($existCerts) {
            foreach ($Cert in $existCerts) {
                $Cert |Remove-Item 
            }
        }


        write-host "Main Domain: $maindomain"
        if (Get-PACertificate -MainDomain $maindomain[0]) {
            # Renew Cert
            write-host "obtaining Renewal Cert: $Cert"
            if ($Force) {
                Submit-Renewal -MainDomain $maindomain[0] -NewKey -Force
            }
            else { 
                Submit-Renewal -MainDomain $maindomain[0] -NewKey
            }
        }
        Else {

            write-host "obtaining new Cert: $Cert"
            #write-host "New-PACertificate $maindomain -DnsPlugin Azure -PluginArgs $azParams -AcceptTOS -PfxPass "$PfxPass""
            if ($Force) {
                $LECert = New-PACertificate $maindomain -DnsPlugin Azure -PluginArgs $azParams -AcceptTOS -PfxPass "$PfxPass" -Force
            }
            else {
                $LECert = New-PACertificate $maindomain -DnsPlugin Azure -PluginArgs $azParams -AcceptTOS -PfxPass "$PfxPass"
            }
            if ($LegacyCert) {
                # Create a CNG cert for PaaS RP.  Least hacky way to do it !
                & cmd /c certutil.exe -f -p $PfxPass -csp "Microsoft Enhanced RSA and AES Cryptographic Provider" -importpfx $($LECert.PfxFile) 
               
            }
            else {
               Import-PfxCertificate -FilePath $LECert.PfxFile cert:\localMachine\my -Password $secPfxPass -Exportable
            }
            $existCerts = Get-ChildItem  Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*$($maindomain[0])"}
            If ($existCerts) {
                $expcertPath = "$Path\$Key\cert.pfx"
                Export-PfxCertificate -Cert $existCerts -Password $secPfxPass -FilePath $expcertPath
                $existCerts | remove-item
            }
            else {
                Write-Debug "Cert not installed"
            }
        }

    }
}

function New-AzsDnsCaaRecords {
    param (
        [Parameter(Mandatory)]
        [string]$ResourceGroup,
        [Parameter(Mandatory)]
        [string]$RegionName,
        [Parameter(Mandatory)]
        [string]$FQDN,
        [string]$mailTo,
        [switch]$ADFS,
        [switch]$AppService,
        [switch]$DBAdapter,
        [Switch]$EventHubs,
        [Switch]$DataBoxEdge,
        [Switch]$IoTHub,
        [Switch]$SkipCore
    )

    function Create-CaaRecord ($ep,$FQDN, $ResourceGroup ) {
        foreach ($Key in $ep.Keys) {

            $epName = $ep[$Key] 
            write-host "EPName:   $epName"

            $caarecords =@()
            $caarecords += New-AzDnsRecordConfig -CaaFlags "0" -CaaTag "iodef" -CaaValue "mailto:$mailTo"
            $caarecords += New-AzDnsRecordConfig -CaaFlags "0" -CaaTag "issue" -CaaValue "letsencrypt.org"
            New-AzDnsRecordSet -Name $epName -RecordType "CAA" -ZoneName $FQDN  -ResourceGroupName $ResourceGroup -Ttl 3600 -DnsRecords $caarecords
            
        }
    }


    if (-not $mailTo) {
        $mailTo = "admin@$RegionName.$FQDN"
    }


    $AzsEndpoints = @{
    
        'Public Portal'="portal.$RegionName";
        'Admin Portal'="adminportal.$RegionName";
        'ARM Public'="management.$RegionName";
        'ARM Admin'="adminmanagement.$RegionName";
        'ACSBlob'="blob.$RegionName";
        'ACSTable'="table.$RegionName";
        'ACSQueue'="queue.$RegionName";
        'KeyVault'="vault.$RegionName";
        'KeyVaultInternal'="adminvault.$RegionName";
        'Admin Extension Host'="adminhosting.$RegionName";
        'Public Extension Host'="hosting.$RegionName"
        }


    $ADFSEndpoints = @{
        'ADFS'="adfs.$RegionName";
        'Graph'="graph.$RegionName";
    }

    $AppSvcEndpoints = @{
            'AppDefault'="scm.appservice.$RegionName";
            'AppSvcWebDefault'="appservice.$RegionName";
            'AppSvcsso'="sso.appservice.$RegionName";
            'AppSvcftp'="ftp.appservice.$RegionName";
            'AppSvcapi'="api.appservice.$RegionName";
            'cloudapp'="$regionName.cloudapp";
    }
    $DBAdapterEndpoints = @{
        'SQLAdapter'="dbadapter.$RegionName"
}
    $EvHubEndPoints = @{
        'EVHubsCert'="eventhub.$RegionName"
    }
    $DataBoxEdgeEndPoints = @{
        'databoxedge'="databoxedge.$RegionName"
    }
    $IotHubEndPoints = @{
        'mgmtiothub'="mgmtiothub.$RegionName"
    }
    
    Get-AzDnsRecordSet -ResourceGroupName $ResourceGroup -ZoneName $FQDN -RecordType CAA
    if (-not $SkipCore){
        Create-CaaRecord -ep $AzsEndpoints -FQDN $FQDN -ResourceGroup $ResourceGroup
    }
    if ($ADFS) {
        Create-CaaRecord -ep $ADFSEndpoints -FQDN $FQDN -ResourceGroup $ResourceGroup
    }
    
    If ($AppService) {
        Create-CaaRecord -ep $AppSvcEndpoints -FQDN $FQDN -ResourceGroup $ResourceGroup
    }
    If ($DBAdapter) {
        Create-CaaRecord -ep $DBAdapterEndpoints -FQDN $FQDN -ResourceGroup $ResourceGroup
    }
    if ($EventHubs){
        Create-CaaRecord -ep $EvHubEndPoints -FQDN $FQDN -ResourceGroup $ResourceGroup
    }
    if ($DataBoxEdge){
         Create-CaaRecord -ep $DataBoxEdgeEndPoints -FQDN $FQDN -ResourceGroup $ResourceGroup
    }
    if ($IoTHub){
         Create-CaaRecord -ep $IotHubEndPoints -FQDN $FQDN -ResourceGroup $ResourceGroup
    }
}

function New-AzsPkiLECertificates {

param(
        [Parameter(Mandatory)]
        [string]$RegionName,
        [Parameter(Mandatory)]
        [string]$FQDN,
        [Parameter(Mandatory)]
        [string]$ServicePrincipal,
        [Parameter(Mandatory)]
        [string]$ServicePrincipalSecret,
        [Parameter(Mandatory)]
        [string]$pfxPass,
        [Parameter(Mandatory)]
        [string]$SubscriptionId,
        [Parameter(Mandatory)]
        [string]$TenantId,
        [string]$CertPath = "",
        [switch]$Staging,
        [Switch]$ADFS,
        [Switch]$AppService,
        [Switch]$DBAdapter,
        [Switch]$EventHubs,
        [Switch]$SkipCore,
        [Switch]$DataBoxEdge,
        [Switch]$IoTHub,
        [switch]$Force
    )

    # Requires the Posh-acme module
    # Requires Azure DNS Zone; Service Principal to create TXT records
    # https://github.com/rmbolger/Posh-ACME/blob/master/Posh-ACME/DnsPlugins/Azure-Readme.md




    # Set the LetsEncrpt environment according to your needs.  For testing, LE_STAGE
    If ($Staging) {
        Set-PAServer LE_STAGE
        write-debug "STAGING Server selected"
    }
    else {
        Set-PAServer LE_PROD
        write-debug "PRODUCTION Server selected"
    }

    If (!(Get-PAAccount)) {
        New-PAAccount -AcceptTOS
    }

    $DNSZone = "$RegionName.$FQDN"
    $secPfxPass = ConvertTo-SecureString -AsPlainText $PfxPass -Force
    $CoreCertPath = "$CertPath\Deployment"
 <#    If ($ADFS) {
        $CoreCertPath = "$CertPath\ADFS"
    } #>
    
    $AppSvcCertPath = "$CertPath\AppServices"
    $DBAdapterCertPath = "$CertPath\DBAdapter"
    $EVHubsCertPath = "$CertPath\EventHubs"
    $DBEHubsCertPath = "$CertPath\DataboxEdge"
    $IoTHubCertPath = "$CertPath\IoTHub"


    $SpPassword = ConvertTo-SecureString $ServicePrincipalSecret -AsPlainText -Force
    $DnsZoneCreds = New-Object System.Management.Automation.PSCredential ($ServicePrincipal, $SpPassword)


    $azParams = @{
        AZSubscriptionId=$SubscriptionId;
        AZTenantId=$TenantId;
        AZAppCred=$DnsZoneCreds
      }

    $AzsCommmonEndpoints = @{
        'Public Portal'="portal.$DNSZone";
        'Admin Portal'="adminportal.$DNSZone";
        'ARM Public'="management.$DNSZone";
        'ARM Admin'="adminmanagement.$DNSZone";
        'ACSBlob'="*.blob.$DNSZone,blob.$DNSZone";
        'ACSTable'="*.table.$DNSZone,table.$DNSZone";
        'ACSQueue'="*.queue.$DNSZone,queue.$DNSZone";
        'KeyVault'="*.vault.$DNSZone,vault.$DNSZone";
        'KeyVaultInternal'="*.adminvault.$DNSZone,adminvault.$DNSZone";
        'Admin Extension Host'="*.adminhosting.$DNSZone,adminhosting.$DNSZone";
        'Public Extension Host'="*.hosting.$DNSZone,hosting.$DNSZone"
        }


    $AzsADFSEndpoints = @{
        'ADFS'="adfs.$DNSZone";
        'Graph'="graph.$DNSZone";
        }




    if (-not (Test-Path -Path $CertPath)) {
        New-Item -ItemType Directory -Path $CertPath
    }
    If (-not $SkipCore){
        new-AzsPACert $AzsCommmonEndpoints -Path $CoreCertPath -azParams $azParams $Force
        if ($ADFS) {
            new-AzsPACert $AzsADFSEndpoints -Path $CoreCertPath -azParams $azParams $Force
            write-debug "Testing ADFS Certificates"
            Invoke-AzsCertificateValidation -CertificateType Deployment -CertificatePath $CoreCertPath -pfxPassword $secPfxPass -RegionName $RegionName -FQDN $FQDN -IdentitySystem ADFS 
        }
        else {
            # Validate the Certs for Azs
            write-debug "Testing AAD Certificates"
            Invoke-AzsCertificateValidation -CertificateType Deployment -CertificatePath $CoreCertPath -pfxPassword $secPfxPass -RegionName $RegionName -FQDN $FQDN -IdentitySystem AAD 
        }
    }
    If ($AppService) {
    
        #Create Certs for all possible PaaS endpoints as there is no cost :)
        # App Service first
        $AZSAppSvcEndPoints = @{
            'DefaultDomain'="*.appservice.$DNSZone,*.scm.appservice.$DNSZone,*.sso.appservice.$DNSZone";
            'API'="api.appservice.$DNSZone";
            'Publishing'="ftp.appservice.$DNSZone";
            'Identity'="sso.appservice.$DNSZone";
        }
        new-AzsPACert $AZSAppSvcEndPoints -Path $AppSvcCertPath -LegacyCert -azParams $azParams $Force
        Invoke-AzsCertificateValidation -CertificateType AppServices -CertificatePath $AppSvcCertPath -pfxPassword $secPfxPass -RegionName $RegionName -FQDN $FQDN

    }
    If ($DBAdapter) {
        # DB Adapter
        $AZSDBAdapterEndPoints = @{
            'DBAdapter'="*.dbadapter.$DNSZone,dbadapter.$DNSZone";
        }
        new-AzsPACert $AZSDBAdapterEndPoints -Path $CertPath -LegacyCert -azParams $azParams $Force
        Invoke-AzsCertificateValidation -CertificateType DBAdapter -CertificatePath $DBAdapterCertPath -pfxPassword $secPfxPass -RegionName $RegionName -FQDN $FQDN
    }

    If ($EventHubs){
        #Create Certs for EventHubs Endpoints
        $AZSEvHubEndPoints = @{
            'EventHubs'="*.eventhub.$DNSZone,*.eventhub.$DNSZone"
        }
        new-AzsPACert $AZSEvHubEndPoints -Path $CertPath -LegacyCert -azParams $azParams $Force
        Invoke-AzsCertificateValidation -CertificateType EventHubs -CertificatePath $EVHubsCertPath -pfxPassword $secPfxPass -RegionName $RegionName -FQDN $FQDN
        #Add capability to test Eventhub Certs when available
    }
    
    If ($DataBoxEdge){
        #Create Certs for Azure Stack Edge GW Endpoints
        $DataBoxEdgeEndPoints = @{
            'databoxedge'="*.databoxedge.$DNSZone,*.databoxedge.$DNSZone"
        }
        new-AzsPACert $DataBoxEdgeEndPoints -Path $CertPath -LegacyCert -azParams $azParams $Force
        # Add Test when available
       
    }
    If ($IotHub){
    #Create Certs for IoTHub Endpoints
    $IotHubEndPoints = @{
        'IoTHub'="*.mgmtiothub.$DNSZone,*.mgmtiothub.$DNSZone"
    }
    new-AzsPACert $IotHubEndPoints -Path $CertPath -LegacyCert -azParams $azParams $Force
    Invoke-AzsCertificateValidation -CertificateType IoTHub -CertificatePath $IoTHubCertPath -pfxPassword $secPfxPass -RegionName $RegionName -FQDN $FQDN
    #Add capability to test DBE Certs when available
    }


     <#
        .SYNOPSIS
            Create PKI Certificates using Lets Encrypt for Azure Stack and validates them for usage.  Requires Microsoft.AzureStack.ReadinessChecker module and Posh-Acme

        .DESCRIPTION
            Uses the Posh-Acme module to create compatible Lets Encrypt PKI certificates for Azure STack.  Used in conjunction with an Azure DNS zone 

        .PARAMETER RegionName
            The Azure Stack region name to generate the certificates for.

        .PARAMETER FQDN
            The FQDN for the Azure Stack deployment.

        .PARAMETER Staging
            If specified, uses the Lets Encrypt staging environment for testing purposes.  It is not rate limited, so is preferrable to use this switch prior to moving to Porduction.

        .PARAMETER ADFS
            If Specified, additional PKI certificates are created for ADFS deployments.

        .PARAMETER AppService
            If specified, generate PKI Certificates required for App Service PaaS.
        cd \user
        .PARAMETER DBAdapter
            If specified, generate PKI Certificates required for SQL/MySQL PaaS.

        .PARAMETER EventHubs
            If specified, generate PKI Certificates required for Event Hubs PaaS.

        .PARAMETER IoTHub
            If specified, generate PKI Certificates required for IoT Hub PaaS.
        .PARAMETER DataBoxEdge
            If specified, generate PKI Certificates required for DataBoxEdge PaaS.

        .PARAMETER Force
            Specifies the output file for which this function saves the response body. Enter a path and file name. If you omit the path, the default is the current location.

        .EXAMPLE

        #>
}
Export-ModuleMember New-AzsPkiLECertificates, new-AzsPACert, New-AzsDnsCaaRecords