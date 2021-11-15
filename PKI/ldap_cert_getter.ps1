 #########
######################################################
## LDAP certificate exporter
## 
## kludged by Ben Knorr Nov15.2021
## 
## exports server and rootCA certificates in PEM format
## from ldap server on tcp/636
##
## USAGE: 
## get-ldapcert
#######################################################

Function Get-LDAPCert {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]$LDAPServerHostNameOrIP,

        [Parameter(Mandatory=$True)]
        [ValidateSet(389,636,3268,3269)]
        [int]$Port,

        [Parameter(Mandatory=$False)]
        [switch]$UseOpenSSL
    )

    ##### BEGIN Helper Functions #####
    #region >> Helper Functions

    function Resolve-Host {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$True)]
            [string]$HostNameOrIP
        )
    
        ## BEGIN Native Helper Functions ##
    
        function Test-IsValidIPAddress([string]$IPAddress) {
            [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
            [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
            Return  ($Valid -and $Octets)
        }
    
        ## END Native Helper Functions ##
        
    
        ##### BEGIN Main Body #####
    
        $RemoteHostNetworkInfoArray = @()
        if (!$(Test-IsValidIPAddress -IPAddress $HostNameOrIP)) {
            try {
                $HostNamePrep = $HostNameOrIP
                [System.Collections.ArrayList]$RemoteHostArrayOfIPAddresses = @()
                $IPv4AddressFamily = "InterNetwork"
                $IPv6AddressFamily = "InterNetworkV6"
    
                $ResolutionInfo = [System.Net.Dns]::GetHostEntry($HostNamePrep)
                $ResolutionInfo.AddressList | Where-Object {
                    $_.AddressFamily -eq $IPv4AddressFamily
                } | foreach {
                    if ($RemoteHostArrayOfIPAddresses -notcontains $_.IPAddressToString) {
                        $null = $RemoteHostArrayOfIPAddresses.Add($_.IPAddressToString)
                    }
                }
            }
            catch {
                Write-Verbose "Unable to resolve $HostNameOrIP when treated as a Host Name (as opposed to IP Address)!"
            }
        }
        if (Test-IsValidIPAddress -IPAddress $HostNameOrIP) {
            try {
                $HostIPPrep = $HostNameOrIP
                [System.Collections.ArrayList]$RemoteHostArrayOfIPAddresses = @()
                $null = $RemoteHostArrayOfIPAddresses.Add($HostIPPrep)
    
                $ResolutionInfo = [System.Net.Dns]::GetHostEntry($HostIPPrep)
    
                [System.Collections.ArrayList]$RemoteHostFQDNs = @() 
                $null = $RemoteHostFQDNs.Add($ResolutionInfo.HostName)
            }
            catch {
                Write-Verbose "Unable to resolve $HostNameOrIP when treated as an IP Address (as opposed to Host Name)!"
            }
        }
    
        if ($RemoteHostArrayOfIPAddresses.Count -eq 0) {
            Write-Error "Unable to determine IP Address of $HostNameOrIP! Halting!"
            $global:FunctionResult = "1"
            return
        }
    
        # At this point, we have $RemoteHostArrayOfIPAddresses...
        [System.Collections.ArrayList]$RemoteHostFQDNs = @()
        foreach ($HostIP in $RemoteHostArrayOfIPAddresses) {
            try {
                $FQDNPrep = [System.Net.Dns]::GetHostEntry($HostIP).HostName
            }
            catch {
                Write-Verbose "Unable to resolve $HostIP. No PTR Record? Please check your DNS config."
                continue
            }
            if ($RemoteHostFQDNs -notcontains $FQDNPrep) {
                $null = $RemoteHostFQDNs.Add($FQDNPrep)
            }
        }
    
        if ($RemoteHostFQDNs.Count -eq 0) {
            $null = $RemoteHostFQDNs.Add($ResolutionInfo.HostName)
        }
    
        [System.Collections.ArrayList]$HostNameList = @()
        [System.Collections.ArrayList]$DomainList = @()
        foreach ($fqdn in $RemoteHostFQDNs) {
            $PeriodCheck = $($fqdn | Select-String -Pattern "\.").Matches.Success
            if ($PeriodCheck) {
                $HostName = $($fqdn -split "\.")[0]
                $Domain = $($fqdn -split "\.")[1..$($($fqdn -split "\.").Count-1)] -join '.'
            }
            else {
                $HostName = $fqdn
                $Domain = "Unknown"
            }
    
            $null = $HostNameList.Add($HostName)
            $null = $DomainList.Add($Domain)
        }
    
        if ($RemoteHostFQDNs[0] -eq $null -and $HostNameList[0] -eq $null -and $DomainList -eq "Unknown" -and $RemoteHostArrayOfIPAddresses) {
            [System.Collections.ArrayList]$SuccessfullyPingedIPs = @()
            # Test to see if we can reach the IP Addresses
            foreach ($ip in $RemoteHostArrayOfIPAddresses) {
                if ([bool]$(Test-Connection $ip -Count 1 -ErrorAction SilentlyContinue)) {
                    $null = $SuccessfullyPingedIPs.Add($ip)
                }
            }
    
            if ($SuccessfullyPingedIPs.Count -eq 0) {
                Write-Error "Unable to resolve $HostNameOrIP! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    
        $FQDNPrep = if ($RemoteHostFQDNs) {$RemoteHostFQDNs[0]} else {$null}
        if ($FQDNPrep -match ',') {
            $FQDN = $($FQDNPrep -split ',')[0]
        }
        else {
            $FQDN = $FQDNPrep
        }
    
        $DomainPrep = if ($DomainList) {$DomainList[0]} else {$null}
        if ($DomainPrep -match ',') {
            $Domain = $($DomainPrep -split ',')[0]
        }
        else {
            $Domain = $DomainPrep
        }
    
        [pscustomobject]@{
            IPAddressList   = [System.Collections.ArrayList]@($(if ($SuccessfullyPingedIPs) {$SuccessfullyPingedIPs} else {$RemoteHostArrayOfIPAddresses}))
            FQDN            = $FQDN
            HostName        = if ($HostNameList) {$HostNameList[0].ToLowerInvariant()} else {$null}
            Domain          = $Domain
        }
    
        ##### END Main Body #####
    
    }

    function Check-Cert {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$True)]
            [string]$IPAddress,
            
            [Parameter(Mandatory=$True)]
            [int]$Port
        )
        
        try {
            $TcpSocket = New-Object Net.Sockets.TcpClient($IPAddress,$Port)
            $tcpstream = $TcpSocket.GetStream()
            $Callback = {param($sender,$cert,$chain,$errors) return $true}
            $SSLStream = New-Object -TypeName System.Net.Security.SSLStream -ArgumentList @($tcpstream, $True, $Callback)
    
            try {
                $SSLStream.AuthenticateAsClient($IPAddress)
                $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($SSLStream.RemoteCertificate)
            }
            finally {
                $SSLStream.Dispose()
            }
        }
        finally {
            $TCPSocket.Dispose()
        }
        
        $Certificate
    }

    #endregion >> Helper Functions
    ##### END Helper Functions #####


    ##### BEGIN Pre-Run Check #####
    #region >> Pre-Run Check

    try {
        $LDAPServerNetworkInfo = Resolve-Host -HostNameOrIP $LDAPServerHostNameOrIP
        if (!$LDAPServerNetworkInfo) {throw "Unable to resolve $LDAPServerHostNameOrIP! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    #endregion >> Pre-Run Check
    ##### END Pre-Run Check #####


    ##### BEGIN Main Body #####
    #region >> Main Body

    if ($UseOpenSSL) {
        # Check is openssl.exe is already available
        if ([bool]$(Get-Command openssl -ErrorAction SilentlyContinue)) {
            # Check to make sure the version is at least 1.1.0
            $OpenSSLExeInfo = Get-Item $(Get-Command openssl).Source
            $OpenSSLExeVersion = [version]$($OpenSSLExeInfo.VersionInfo.ProductVersion -split '-')[0]
        }

        # We need at least vertion 1.1.0 of OpenSSL
        if ($OpenSSLExeVersion.Major -lt 1 -or 
        $($OpenSSLExeVersion.Major -eq 1 -and $OpenSSLExeVersion.Minor -lt 1)
        ) {
            [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
            $OpenSSLWinBinariesUrl = "http://wiki.overbyte.eu/wiki/index.php/ICS_Download"
            $IWRResult = Invoke-WebRequest -Uri $OpenSSLWinBinariesUrl
            $LatestOpenSSLWinBinaryLinkObj = $($IWRResult.Links | Where-Object {$_.innerText -match "OpenSSL Binaries" -and $_.href -match "\.zip"})[0]
            $LatestOpenSSLWinBinaryUrl = $LatestOpenSSLWinBinaryLinkObj.href
            $OutputFileName = $($LatestOpenSSLWinBinaryUrl -split '/')[-1]
            $OutputFilePath = "$HOME\Downloads\$OutputFileName"
            Invoke-WebRequest -Uri $LatestOpenSSLWinBinaryUrl -OutFile $OutputFilePath

            if (!$(Test-Path "$HOME\Downloads\$OutputFileName")) {
                Write-Error "Problem downloading the latest OpenSSL Windows Binary from $LatestOpenSSLWinBinaryUrl ! Halting!"
                $global:FunctionResult = "1"
                return
            }

            $OutputFileItem = Get-Item $OutputFilePath
            $ExpansionDirectory = $OutputFileItem.Directory.FullName + "\" + $OutputFileItem.BaseName
            if (!$(Test-Path $ExpansionDirectory)) {
                $null = New-Item -ItemType Directory -Path $ExpansionDirectory -Force
            }
            else {
                Remove-Item "$ExpansionDirectory\*" -Recurse -Force
            }

            $null = Expand-Archive -Path "$HOME\Downloads\$OutputFileName" -DestinationPath $ExpansionDirectory -Force

            # Add $ExpansionDirectory to $env:Path
            $CurrentEnvPathArray = $env:Path -split ";"
            if ($CurrentEnvPathArray -notcontains $ExpansionDirectory) {
                # Place $ExpansionDirectory at start so latest openssl.exe get priority
                $env:Path = "$ExpansionDirectory;$env:Path"
            }
        }

        if (![bool]$(Get-Command openssl -ErrorAction SilentlyContinue)) {
            Write-Error "Problem setting openssl.exe to `$env:Path! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($Port -eq 389 -or $Port -eq 3268) {
        if (!$UseOpenSSL) {
            Write-Error "Unable to get LDAP Certificate on port $Port using StartTLS without openssl.exe! Try the -UseOpenSSL switch. Halting!"
            $global:FunctionResult = "1"
            return
        }

        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        #$ProcessInfo.WorkingDirectory = $BinaryPath | Split-Path -Parent
        $ProcessInfo.FileName = $(Get-Command openssl).Source
        $ProcessInfo.RedirectStandardError = $true
        $ProcessInfo.RedirectStandardOutput = $true
        #$ProcessInfo.StandardOutputEncoding = [System.Text.Encoding]::Unicode
        #$ProcessInfo.StandardErrorEncoding = [System.Text.Encoding]::Unicode
        $ProcessInfo.UseShellExecute = $false
        $ProcessInfo.Arguments = "s_client -connect $($LDAPServerNetworkInfo.FQDN):$Port -starttls ldap -showcerts"
        $Process = New-Object System.Diagnostics.Process
        $Process.StartInfo = $ProcessInfo
        $Process.Start() | Out-Null
        # Sometimes openssl.exe hangs, so, we'll give it 5 seconds before killing
        # Below $FinishedInAlottedTime returns boolean true/false
        $FinishedInAlottedTime = $Process.WaitForExit(5000)
        if (!$FinishedInAlottedTime) {
            $Process.Kill()
        }
        $stdout = $Process.StandardOutput.ReadToEnd()
        $stderr = $Process.StandardError.ReadToEnd()
        $OpenSSLResult = $stdout + $stderr

        # Parse the output of openssl
        $OpenSSLResultLineBreaks = $OpenSSLResult -split "`n"
        $IndexOfBeginCert = $OpenSSLResultLineBreaks.IndexOf($($OpenSSLResultLineBreaks -match "BEGIN CERTIFICATE"))
        $IndexOfEndCert = $OpenSSLResultLineBreaks.IndexOf($($OpenSSLResultLineBreaks -match "End CERTIFICATE"))

        if ($IndexOfBeginCert -eq "-1" -or $IndexOfEndCert -eq "-1") {
            Write-Error "Unable to find Certificate in openssl output! Halting!"
            $global:FunctionResult = "1"
            return
        }
        
        $PublicCertInPemFormat = $OpenSSLResultLineBreaks[$IndexOfBeginCert..$IndexOfEndCert]

        # Get $X509Cert2Obj
        $PemString = $($PublicCertInPemFormat | Where-Object {$_ -notmatch "CERTIFICATE"}) -join "`n"
        $byteArray = [System.Convert]::FromBase64String($PemString)
        $X509Cert2Obj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($byteArray)
    }

    if ($Port -eq 636 -or $Port -eq 3269) {
        if ($UseOpenSSL) {
            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
            #$ProcessInfo.WorkingDirectory = $BinaryPath | Split-Path -Parent
            $ProcessInfo.FileName = $(Get-Command openssl).Source
            $ProcessInfo.RedirectStandardError = $true
            $ProcessInfo.RedirectStandardOutput = $true
            #$ProcessInfo.StandardOutputEncoding = [System.Text.Encoding]::Unicode
            #$ProcessInfo.StandardErrorEncoding = [System.Text.Encoding]::Unicode
            $ProcessInfo.UseShellExecute = $false
            $ProcessInfo.Arguments = "s_client -connect $($LDAPServerNetworkInfo.FQDN):$Port"
            $Process = New-Object System.Diagnostics.Process
            $Process.StartInfo = $ProcessInfo
            $Process.Start() | Out-Null
            # Sometimes openssl.exe hangs, so, we'll give it 5 seconds before killing
            # Below $FinishedInAlottedTime returns boolean true/false
            $FinishedInAlottedTime = $Process.WaitForExit(5000)
            if (!$FinishedInAlottedTime) {
                $Process.Kill()
            }
            $stdout = $Process.StandardOutput.ReadToEnd()
            $stderr = $Process.StandardError.ReadToEnd()
            $OpenSSLResult = $stdout + $stderr

            # Parse the output of openssl
            $OpenSSLResultLineBreaks = $OpenSSLResult -split "`n"
            $IndexOfBeginCert = $OpenSSLResultLineBreaks.IndexOf($($OpenSSLResultLineBreaks -match "BEGIN CERTIFICATE"))
            $IndexOfEndCert = $OpenSSLResultLineBreaks.IndexOf($($OpenSSLResultLineBreaks -match "End CERTIFICATE"))
            
            if ($IndexOfBeginCert -eq "-1" -or $IndexOfEndCert -eq "-1") {
                Write-Error "Unable to find Certificate in openssl output! Halting!"
                $global:FunctionResult = "1"
                return
            }

            $PublicCertInPemFormat = $OpenSSLResultLineBreaks[$IndexOfBeginCert..$IndexOfEndCert]

            # Get $X509Cert2Obj
            $PemString = $($PublicCertInPemFormat | Where-Object {$_ -notmatch "CERTIFICATE"}) -join "`n"
            $byteArray = [System.Convert]::FromBase64String($PemString)
            $X509Cert2Obj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($byteArray)
        }
        else {
            $X509Cert2Obj = Check-Cert -IPAddress $LDAPServerNetworkInfo.IPAddressList[0] -Port $Port
            $PublicCertInPemFormatPrep = "-----BEGIN CERTIFICATE-----`r`n" + 
                [System.Convert]::ToBase64String($X509Cert2Obj.RawData, [System.Base64FormattingOptions]::InsertLineBreaks) + 
                "`r`n-----END CERTIFICATE-----"
            $PublicCertInPemFormat = $PublicCertInPemFormatPrep -split "`n"
        }
    }

    $CertificateChain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    $null = $CertificateChain.Build($X509Cert2Obj)
    $RootCAX509Cert2Obj = $CertificateChain.ChainElements.Certificate | Where-Object {$_.Issuer -eq $_.Subject}
    $RootCAPublicCertInPemFormatPrep = "-----BEGIN CERTIFICATE-----`r`n" + 
        [System.Convert]::ToBase64String($RootCAX509Cert2Obj.RawData, [System.Base64FormattingOptions]::InsertLineBreaks) + 
        "`r`n-----END CERTIFICATE-----"
    $RootCACertInPemFormat = $RootCAPublicCertInPemFormatPrep -split "`n"

    $LDAPEndpointCertificateInfo = [pscustomobject]@{
        X509CertFormat      = $X509Cert2Obj
        PemFormat           = $PublicCertInPemFormat
    }

    $RootCACertificateInfo = [pscustomobject]@{
        X509CertFormat      = $RootCAX509Cert2Obj
        PemFormat           = $RootCACertInPemFormat
    }

    [pscustomobject]@{
        LDAPEndpointCertificateInfo  = $LDAPEndpointCertificateInfo
        CertificateChain             = $CertificateChain
        RootCACertificateInfo        = $RootCACertificateInfo
    }
    
    $RootCACertInPemFormat |Out-File CAcert.pem -NoNewline
    $LDAPEndpointCertificateInfo |Out-File LDAPcert.pem -NoNewline
    write-host "wrote files to $pwd`n" -ForegroundColor Green

    #endregion >> Pre-Run Check
    ##### END Main Body #####
} 
