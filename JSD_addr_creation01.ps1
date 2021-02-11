####################
##
##
##
## this script will do some things with panorama or palo firewalls.
## written by ben knorr, bknorr@compunet.biz
## run this script at your own risk; no warranties expressed or implied.
## and wash your hands!
#####################

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
    $panOSversion="v" + (((Invoke-RestMethod -Uri "https://$panHost/api/?type=version&key=$($key)" -Method post).response.result."sw-version").split('.')[0,1] -join '.')
    write-host "SUCCESS : good hostname and credential." -ForegroundColor Green
}
catch{
    Clear-Variable cred,key -ErrorAction SilentlyContinue
    write-host "FAIL : something didn't work. bye!"
    write-host $error[0] -ForegroundColor Red
    $error.clear()
    break
}

##################### queryPan is what will interact with restAPI. This isn't designed to work with non panorma devices yet.
function queryPAN {
    ## this should include api get
    [CmdletBinding()]
        param(
            [Parameter(ValueFromPipeline = $true)]
            [String[]]$APIargs,
            [String[]]$Method,
            [String[]]$Body,
            [String[]]$objPath
        )
    Invoke-RestMethod -Uri "https://$panHost/restapi/$panOSversion/$objPath`?$apiargs" -Headers $headers -Method $Method -Body $Body
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
        $ip_S=$line.ipaddr.split('.')
        $ip_S[2]="22"
        $ip_S=$($ip_S -join '.')+"/24"
        $desc_S="$($line.LongName) SWITCHES"
        $name_S="$($line.schoolID)_SWITCHES"

        $body=@{entry=@{}}
        $body.entry.add("ip-netmask","$ip_S")
        $body.entry.add("@name","$name_S")
        $body.entry.add("description","$desc_S")
        $body=$body | ConvertTo-Json -Depth 99

        $switchNames+=$name_S

        # set object in panorama
        queryPAN -APIargs "name=$name_S&location=device-group&device-group=$source_DG" -Method "post" -body $body -objPath "Objects/Addresses"

        ## Set wireless switch network objects for each school
        $ip_W=$line.ipaddr.split('.')
        $ip_W[2]="23"
        $ip_W=$($ip_W -join '.')+"/24"
        $desc_W="$($line.LongName) WIRELESS SWITCHES"
        $name_W="$($line.schoolID)_WIRELESS_SWITCHES"

        $body=@{entry=@{}}
        $body.entry.add("ip-netmask","$ip_W")
        $body.entry.add("@name","$name_W")
        $body.entry.add("description","$desc_W")
        $body=$body | ConvertTo-Json -Depth 99

        $wirelessSwitchNames+=$name_W

        # set object in panorama
        queryPAN -APIargs "name=$name_W&location=device-group&device-group=$source_DG" -Method "post" -body $body -objPath "Objects/Addresses"

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
    queryPAN -APIargs "name=JSD_SCHOOL_SWITCHES&location=device-group&device-group=$source_DG" -Method "post" -body $body -objPath "Objects/AddressGroups"

    ## wireless switch addr groups...
    $body=@{entry=@{static=@()}}
    $body.entry.add("@name","JSD_SCHOOL_WIRELESS_SWITCHES")
    $body.entry.add("description","JSD School Wireless Switches")
    $tempBody=@{member=$wirelessSwitchNames}
    $body.entry.static+=$tempBody
    $body=$body | ConvertTo-Json -Depth 99

    # set address group object in panorama
    queryPAN -APIargs "name=JSD_SCHOOL_WIRELESS_SWITCHES&location=device-group&device-group=$source_DG" -Method "post" -body $body -objPath "Objects/AddressGroups"

    Clear-Variable panorama_DGs,key
    write-host "done!"
}
else
{
    ## PanOS Firewall section
    write-host "this script isn`'t designed to support this function yet"
}
