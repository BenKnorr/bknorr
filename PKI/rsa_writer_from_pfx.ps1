 # mostly stolen from the follwoing 
#https://github.com/Devolutions/WaykNow-ps/blob/master/WaykNow/Private/RSAHelper.ps1 
#https://stackoverflow.com/questions/23734792/c-sharp-export-private-public-rsa-key-from-rsacryptoserviceprovider-to-pem-strin
# pass a PFX and get the base64/PEM of the privatekey 

## Added by BenK:
## this script accepts 1 parameter (pfx file path).
##    usage:   .\rsa_writer_from_pfx.ps1 .\somepath\yourPFXfile.pfx
##
## RSA private key and public key will be written to the same path\filename 
## as the source .pfx file, with .key and .pem extensions respectively.
## No ACE is applied to the private key : please treat this file carefully!


param (
            
    [string]$PFXPath = ""

)
function Get-PrivKey(
[System.Security.Cryptography.RSAParameters]$RSAParams
){
[byte]$Sequence = 0x30 
[byte[]]$Version =(0x00)
$stream = [System.IO.MemoryStream]::new()
$writer = [System.IO.BinaryWriter]::new($stream)
$writer.Write($Sequence); # SEQUENCE
$innerStream = [System.IO.MemoryStream]::new()
$innerWriter = [System.IO.BinaryWriter]::new($innerStream)

EncodeIntegerBigEndian $innerWriter $Version
EncodeIntegerBigEndian $innerWriter $RSAParams.Modulus
EncodeIntegerBigEndian $innerWriter $RSAParams.Exponent
EncodeIntegerBigEndian $innerWriter $RSAParams.D
EncodeIntegerBigEndian $innerWriter $RSAParams.P
EncodeIntegerBigEndian $innerWriter $RSAParams.Q
EncodeIntegerBigEndian $innerWriter $RSAParams.DP
EncodeIntegerBigEndian $innerWriter $RSAParams.DQ
EncodeIntegerBigEndian $innerWriter $RSAParams.InverseQ

$length = ([int]($innerStream.Length))
EncodeLength $writer $length
$writer.Write($innerStream.GetBuffer(), 0, $length)

$base64 = [Convert]::ToBase64String($stream.GetBuffer(), 0, ([int]($stream.Length)))

$offset = 0
$line_length = 64

$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine("-----BEGIN RSA PRIVATE KEY-----")
while ($offset -lt $base64.Length) {
$line_end = [Math]::Min($offset + $line_length, $base64.Length)
[void]$sb.AppendLine($base64.Substring($offset, $line_end - $offset))
$offset = $line_end
}

[void]$sb.AppendLine("-----END RSA PRIVATE KEY-----")

return $sb.ToString()
}

function EncodeLength(
[System.IO.BinaryWriter]$stream,
[int]$length
){
[byte]$bytex80 = 0x80
if($length -lt 0){
throw "Length must be non-negative"
}
if($length -lt $bytex80){
$stream.Write(([byte]$length))
}
else{
$temp = $length
$bytesRequired = 0;
while ($temp -gt 0) {
    $temp = $temp -shr 8
    $bytesRequired++
}

[byte]$byteToWrite = $bytesRequired -bor $bytex80
$stream.Write($byteToWrite)
$iValue = ($bytesRequired - 1)
[byte]$0ffByte = 0xff
for ($i = $iValue; $i -ge 0; $i--) {
    [byte]$byteToWrite = ($length -shr (8 * $i) -band $0ffByte)
    $stream.Write($byteToWrite )
}
}
}

function EncodeIntegerBigEndian(
[System.IO.BinaryWriter]$stream,
[byte[]]$value,
[bool]$forceUnsigned = $true
)
{
[byte]$Integer = 0x02

$stream.Write($Integer); # INTEGER
$prefixZeros = 0
for ($i = 0; $i -lt $value.Length; $i++) {
if ($value[$i] -ne 0){break} 
$prefixZeros++
}
if(($value.Length - $prefixZeros) -eq 0){
EncodeLength $stream 1
$stream.Write(([byte]0))
}
else{
[byte]$newByte = 0x7f
if(($forceUnsigned) -AND ($value[$prefixZeros] -gt $newByte)){
    EncodeLength $stream ($value.Length - $prefixZeros +1)
    $stream.Write(([byte]0))
}
else{
    EncodeLength $stream ($value.Length - $prefixZeros)
}
for ($i = $prefixZeros; $i -lt $value.Length; $i++) {
    $stream.Write($value[$i])
}
}
}
function Get-RSAKeyData([String]$PFXPath)
{
if(Test-Path $PFXPath){
$PFXPath=(Resolve-Path $PFXPath).Path
$script:Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2    
$PFXPassword = Read-Host -AsSecureString 'Enter PFX password'
$CertFlags = New-Object System.Security.Cryptography.X509Certificates.X509KeyStorageFlags
$CertFlags.value__ = 4 #exportable
$Cert.Import($PFXPath,$PFXPassword,$CertFlags)
$PrivateKeyParams = $Cert.PrivateKey.ExportParameters($true)
return $PrivateKeyParams
}
else{
 Write-Error 'That pfx does not exist'    
}
}

function Get-CertAsPEM([string]$PFXPath,$cert) {

## added by BenK
## this portion gets $cert that was imported in Get-RSAKeyData function, exports it in base64 format
## to the same path where the original source .pfx came from with .pem extension.
##

if (test-path $pfxpath){
$PFXPath=(Resolve-Path $PFXPath).Path
$base64CertText = [System.Convert]::ToBase64String($cert.RawData, "InsertLineBreaks")

$out = New-Object String[] -ArgumentList 3

$out[0] = "-----BEGIN CERTIFICATE-----"
$out[1] = $base64CertText
$out[2] = "-----END CERTIFICATE-----"
try {
    $out | Out-File $($PFXPath.replace('.pfx','.pem')) -ErrorAction stop -Force
    write-host "we wrote a public key to $($PFXPath.replace('.pfx','.pem'))" -ForegroundColor Green
}
catch{
    Write-Error 'we had trouble writing the public key'
}
}
}

try{
$PrivateKeyParams = Get-RSAKeyData($PFXPath)
$PrivateKey = Get-PrivKey($PrivateKeyParams)
write-host $PrivateKey -ForegroundColor Cyan
$publicKey = Get-CertAsPEM $PFXPath $cert

## added by BenK
## write the RSA private key to the original .pfx source path with .key extension.
##

$PFXPath=(Resolve-Path $PFXPath).Path
$PrivateKey |Out-File -FilePath $PFXPath.replace('.pfx','.key') -Force 
write-host "`nwe wrote a RSA private key to $($PFXPath.replace('.pfx','.key'))" -ForegroundColor Green
write-host "`nthe private key was written in clear-text and has inherited permissions from the folder where it was created." -ForegroundColor red
write-host " ### Please take care of this key and ensure it is not readable by regular users or transmitted insecurely! ###" -foregroundcolor red

}
catch{
Write-host $error[0] -ForegroundColor red
} 
