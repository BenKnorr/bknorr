####################
##
##
##
## this script will do some things with panorama or palo firewalls.
## written by ben knorr, bknorr@compunet.biz
## run this script at your own risk; no warranties expressed or implied.
## and wash your hands!
#####################

try{
    add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}
catch{
    write-host "Could not bypass SSL certificate checking. If errors occur, please add PAN device certificate to this computer's trusted certificates store." -ForegroundColor yellow
}
    
##################### bypassing TLS strict enforcement : not needed in all environments
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
##################### /bypass cert validation

##################### get credentials and pan device info
$panHost=read-host "Please enter the address of your Panorama or Strata firewall"
$cred=Get-Credential -Message "Please enter a valid user/password with API access to your Pan device"
$panorama=@('M-100','M-300','M-500','panorama','Panorama')
##################### /creds

$JSD_logFile="JSD_unusedAddr_Fixer_$((get-date).ToString('%M.%d.%y-%H%m%s')).log"

##################### get API key
try {
    $key=(Invoke-RestMethod -Uri "https://$panHost/api/?type=keygen&user=$($cred.userName)&password=$($cred.GetNetworkCredential().password)" -Method post).response.result.key 
    Clear-Variable cred -ErrorAction SilentlyContinue
    $headers=@{'X-PAN-KEY' = $key}
    $headers.Add("Content-Type", "application/json")
    $panOSversion=(((Invoke-RestMethod -Uri "https://$panHost/api/?type=version&key=$($key)" -Method post).response.result."sw-version").split('.')[0,1] -join '.')
    if ($panOSversion -notlike "9.0"){
        $panOSversion= "v" + $panOSversion
    }
    write-host "SUCCESS : good hostname and credential." -ForegroundColor Green
}
catch{
    Clear-Variable cred,key -ErrorAction SilentlyContinue
    write-host "FAIL : something didn't work. bye!"
    write-host $error[0] -ForegroundColor Red
    $error.clear()
    break
}
##################### /get API key


##################### queryPan is what will interact with restAPI. This isn't designed to work with non panorama devices yet.
function queryPAN {
    ## this should include api get
    [CmdletBinding()]
        param(
            [Parameter(ValueFromPipeline = $true)]
            [String[]]$APIargs,
            [String[]]$Method,
            [String[]]$Body,
            [String[]]$objPath,
            [String[]]$obj_name,
            [String[]]$logpath
        )
    Clear-Variable error
    try{
        Invoke-RestMethod -Uri "https://$panHost/restapi/$panOSversion/$objPath`?$apiargs" -Headers $headers -Method $Method -Body $Body
        write-host "success on $obj_name"
        Write-Output "[ $($obj_name) ] : Successfully deleted" |Add-Content $logpath
    }
    catch{
        write-host "failed on $obj_name" -ForegroundColor red
        write-host $error[0] -ForegroundColor red
        Write-Output "[ $($obj_name) ] : FAILED in $obj_name : $error[0]" |Add-Content $logpath
    }
}
##################### /queryPan


##################### identify if target device is FW or Panorama. Using XML api here for some reason.
$get=Invoke-RestMethod -Uri "https://$panHost/api/?type=version" -Headers $headers -Method "get" 
if ($panorama -contains $get.response.result.model){
    Write-Host "FW TYPE : PANORAMA" -ForegroundColor Green
    #queryPAN -apiargs "type=config&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group" -Method "get"
    $get=Invoke-RestMethod -Uri "https://$panHost/api/?type=config&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group" -Headers $headers -Method "get" 
    Write-Host "`n"
    $panorama_DGs=$get.response.result.'device-group'.entry.name
    Clear-Variable get
}
else{
    write-host "FW TYPE : not panorama! $($get.response.result.model)" -ForegroundColor Green
}
##################### /ID device type



## add text to show what this script will do
write-host "This script will attempt to find addresses that are generic in nature and are not used.`r
criteria:`r
`tunused (from expedition report)`r
`taddress name is a valid IP or range with `- separator`r
`taddress object does not have a description" -ForegroundColor DarkCyan
sleep 7

$panorama_DGs

## query for device-group to work on: should be base or shared
$dgTargetSelected=read-host "Enter the device-group to work on (or `"shared`")"
if ($dgTargetSelected -cnotlike "shared"){
    $apiArgs="LOCATION=device-group&output-format=json"
    $apiargs+="&device-group=$dgTargetSelected"
}
else{
    $apiArgs="LOCATION=shared&output-format=json"    
}
$JSD_addressObjects=queryPAN -objPath "Objects/Addresses" -APIargs $apiArgs -Method get -obj_name $dgTargetSelected -logpath $JSD_logFile

##### DEFINE THIS PLEASE!!!! ######
$JSD_expeditionReport=import-csv "/Users/bknorr/Documents/OneDrive - CompuNet, Inc/clients/Jordan School District/addrCleanup/Ex_address.csv"|Where-Object {$_.USED -eq "Unused"}
# $jsd_expeditionReport only includes unused addresses here
###################################

write-host "THIS SCRIPT WILL DELETE A BUNCH OF ADDRESS OBJECTS: IF YOU WANT TO CONTINUE, ENTER `"Y or y`"." -ForegroundColor Red
$selector=read-host "choice"
if ($selector -notmatch "y"){
    write-host "bye!"
    sleep 3
    exit
}

$i=0
$time=get-date    
foreach ($addr in $JSD_addressObjects.result.entry){
    $apiArgs="LOCATION=device-group&output-format=json"
    $apiargs+="&device-group=$dgTargetSelected"
    $apiArgs+="&name=$($addr.'@name')"
    
    ##
    ##

    if ($JSD_expeditionReport.NAME -match $addr.'@name'){
        if ($null -ne $addr.'ip-netmask'){
            #only working on ip-netmask here
            if (($null -eq $addr.description) -and ($addr.'@name' -match "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$" )){
                #
                # finding addresses that do not have descriptions (maybe added by expedition or script?)
                # finding addresses that have a name which can only be a valid IP address (no text)
                # deleting them individually...
                queryPAN -objPath "Objects/Addresses" -APIargs $apiArgs -obj_name $($addr.'@name') -logpath $JSD_logFile -Method "DEL"
            }
        }
        elseif ($null -ne $addr.'ip-range'){
            #only working on ip-range here
            if (($null -eq $addr.description) -and ($addr.'@name' -match "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\-(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$" )){
                #
                # finding addresses ranges that do not have descriptions (maybe added by expedition or script?)
                # finding addresses ranges that have a name which can only be a valid IP address , a "-" and another valid IP address (no text)
                # deleting them individually...
                queryPAN -objPath "Objects/Addresses" -APIargs $apiArgs -obj_name $($addr.'@name') -logpath $JSD_logFile -Method "DEL"
            }
        }
    }
    $percentComplete=($i/$JSD_addressObjects.result.entry.count)*100
    $i++
    Write-Progress -Activity "Deleting things, starting at $time" -Status "$i of $($JSD_addressObjects.result.entry.count) potential objects in $dgTargetSelected" -PercentComplete $percentComplete
}
write-host "Done!`nPlease commit changes manually. have a good day!" -ForegroundColor Green
