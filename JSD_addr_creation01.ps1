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

##################### file
write-host "This script will consume ip address data in 'data.csv' which needs to be located in the current working directory."
sleep 5
try{
    Test-Path -Path data.csv -ErrorAction Stop
    $data=import-csv data.csv
}
catch{
    write-host "data.csv is not present. try again" -ForegroundColor Red
    break
}

##################### get credentials and pan device info
$panHost=read-host "Please enter the address of your Panorama or Strata firewall"
$cred=Get-Credential -Message "Please enter a valid user/password with API access to your Pan device"
$panorama=@('M-100','M-300','M-500','panorama','Panorama')

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
            [String[]]$obj_name
        )
    try{
        Invoke-RestMethod -Uri "https://$panHost/restapi/$panOSversion/$objPath`?$apiargs" -Headers $headers -Method $Method -Body $Body
        write-host "success on $obj_name"
    }
    catch{
        write-host "failed on $obj_name" -ForegroundColor red
        write-host $error[0] -ForegroundColor red
    }
}

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

##################### 
## custom JSD stuff
if ($null -ne $panorama_DGs){
    write-host "This script will read address items in a device group and do several things:
    -Feb10.2021:
    -consume data from `"data.csv`" including ip addresses, names
    -create address objects based on this for `"wireless switches`" x.x.23.0/24 and `"switches`" x.x.22.0/24
    -create address groups for these objects
    `n"
    $panorama_DGs
    write-host "`n"
    $source_DG=Read-Host "Please enter the Device Group you will be working with: "
    write-host "We will be running restapi from here on out, and will be actively pushing individual changes to Panorama. this might take a minute..." -ForegroundColor cyan
    sleep 5
    ##################### defining address group static member arrays
    $switchNames=@()
    $wirelessSwitchNames=@()
    ##################### walking through each line in csv file, getting info for each addr and creating address individual address objects
    foreach ($line in $data){
        ## Set switch network objects for each school
        # splitting the ip address in the most inefficient way possible so we can change the value of an octet in next step
        $ip_S=$line.ipaddr.split('.')
        # changing third octet to value in quotes
        $ip_S[2]="22"
        # putting it back together into ip address in CIDR notation (change CIDR as needed)
        $ip_S=$($ip_S -join '.')+"/24"
        # assigning IP addr description
        $desc_S="$($line.LongName) SWITCHES"
        # assigning IP addr name
        $name_S="$($line.schoolID)_SWITCHES"

        $body=@{entry=@{}}
        $body.entry.add("ip-netmask","$ip_S")
        $body.entry.add("@name","$name_S")
        $body.entry.add("description","$desc_S")
        $body=$body | ConvertTo-Json -Depth 99

        $switchNames+=$name_S

        # set object in panorama
        queryPAN -APIargs "name=$name_S&location=device-group&device-group=$source_DG" -Method "post" -body $body -objPath "Objects/Addresses" -obj_name $name_S
        ## end of switch address section

        ## Set wireless switch network objects for each school
        # splitting the ip address in the most inefficient way possible so we can change the value of an octet in next step        
        $ip_W=$line.ipaddr.split('.')
        # changing third octet to value in quotes
        $ip_W[2]="23"
        # putting it back together into ip address in CIDR notation (change CIDR as needed)
        $ip_W=$($ip_W -join '.')+"/24"
        # assigning IP addr description
        $desc_W="$($line.LongName) WIRELESS SWITCHES"
        # assigning IP addr name
        $name_W="$($line.schoolID)_WIRELESS_SWITCHES"

        $body=@{entry=@{}}
        $body.entry.add("ip-netmask","$ip_W")
        $body.entry.add("@name","$name_W")
        $body.entry.add("description","$desc_W")
        $body=$body | ConvertTo-Json -Depth 99

        $wirelessSwitchNames+=$name_W

        # set object in panorama
        queryPAN -APIargs "name=$name_W&location=device-group&device-group=$source_DG" -Method "post" -body $body -objPath "Objects/Addresses" -obj_name $name_W
        ## end of wireless address section
    }
    
    ##################### Address groups...
    ## switch addr groups...
    $body=@{entry=@{static=@()}}
    $body.entry.add("@name","JSD_SCHOOL_SWITCHES")
    $body.entry.add("description","JSD School Switches")
    $tempBody=@{member=$switchNames}
    $body.entry.static+=$tempBody
    $body=$body | ConvertTo-Json -Depth 99

    # set address group object in panorama
    queryPAN -APIargs "name=JSD_SCHOOL_SWITCHES&location=device-group&device-group=$source_DG" -Method "post" -body $body -objPath "Objects/AddressGroups" -obj_name "JSD_SCHOOL_SWITCHES"
    ## end of switch addr groups...

    ## wireless switch addr groups...
    $body=@{entry=@{static=@()}}
    $body.entry.add("@name","JSD_SCHOOL_WIRELESS_SWITCHES")
    $body.entry.add("description","JSD School Wireless Switches")
    $tempBody=@{member=$wirelessSwitchNames}
    $body.entry.static+=$tempBody
    $body=$body | ConvertTo-Json -Depth 99

    # set address group object in panorama
    queryPAN -APIargs "name=JSD_SCHOOL_WIRELESS_SWITCHES&location=device-group&device-group=$source_DG" -Method "post" -body $body -objPath "Objects/AddressGroups" -obj_name "JSD_SCHOOL_WIRELESS_SWITCHES"
    ## end of wireless switch addr groups...

    Clear-Variable panorama_DGs,key
    write-host "done!"
}
else
{
    ## PanOS Firewall section
    write-host "this script isn`'t designed to support this function yet"
}
