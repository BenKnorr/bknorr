 ## this script generates a self-signed certificate code signing certificate and places a copy in TrustedPublishers;
## it should only be used for script that execute on THIS SYSTEM.
##
## usage:
##     -run this script once to create a self-signed code-signing certificate for use on this system.
##
##     -run this script and use "signScripts" function to sign any powershell scripts/modules.     
##       examples:
##     signScripts yourPowershellScript.ps1
##     signScripts c:\users\joeuser\powershellscript.ps1m
##
## 
## use at your own risk!
## march 22.2022
## written by Ben Knorr
##


function signScripts {
    #this will use the newest code signing cert in Cert:\localmachine\my.
    param (
    [string[]]$scriptToSign
    )

    $ben=Set-AuthenticodeSignature -Certificate (Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert | Sort-Object -Descending -Property NotBefore)[0] -FilePath $scriptToSign -TimestampServer "http://timestamp.digicert.com"
    Write-Output $ben
}

write-host "do you want to create a new self-signed code signing cert? (y/n): " -ForegroundColor Yellow -NoNewline
$selector=read-host
if ($selector -match "y"){
    write-host "please enter a certificate subject. a common name at a minimum is recommended, eg. `"cn=Ben's PC self code signing`" (no quotes needed)" -ForegroundColor Yellow
    $subject=read-host
    $certContainer="localmachine"
    $certStore="My"
    $certDstStore="TrustedPublisher"
    $certDstContainer=$certContainer
    $certStoreLocation="Cert:\$($certContainer)\$($certStore)"
    $certDstStoreRoot="Root"
    
    try{
        ## create a self signed code-sining certificate in $certstorelocation
        $newCert=New-SelfSignedCertificate -type CodeSigningCert -Subject $subject -KeyLength 2048 -KeyAlgorithm RSA -CertStoreLocation $certStoreLocation -ErrorAction stop
        write-host "succcessfully created the certificate in $container." -ForegroundColor cyan
     
        ## copy the certificate to trusted publishers container
        $destContainer=New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store $certDstStore,$certDstContainer
        $destContainer.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $destContainer.Add($newcert[0])
        write-host "copied certificate to $certContainer\$certDstStore" -ForegroundColor Cyan

        ## copy the certificate to trusted root certification authorities container
        $destRootContainer=New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store $certDstStoreRoot,$certDstContainer
        $destRootContainer.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $destRootContainer.Add($newcert[0])
        write-host "copied certificate to $certContainer\$certDstStoreRoot" -ForegroundColor Cyan
        
        ## close all the containers when done
        $sourceContainer.Close()
        $destContainer.Close()
        $destRootContainer.Close()
    }
    catch{
        write-host "something didn't work while making a code signing cert."
        write-output $error[0]
    }
}
write-host "Digitally sign scripts using the `"signScripts`" function." -ForegroundColor Green 
