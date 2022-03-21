## test file to check module functionality! ##

Import-Module /Users/bknorr/Documents/GitHub/bknorr/PAN/ben_PAN.psm1 -Force

##############################################################
## required params that need to be gathered in this script
## $pan1 , $cred1 , $pan2 , $cred2
##############################################################

write-host "What is your IP or hostname of PAN that you want to work with?" -ForegroundColor yellow
$pan1=Read-Host
Get-PanAPIkey -pan1 $pan1

# 1- CHECK PAN LICENSE
write-host "checking PAN license"
Invoke-panXMLapi -Type "op" -cmd "<request><license><info></info></license></request>" -Pan1 $pan1

# 2- CHECK , DOWNLOAD, INSTALL APPS
write-host "do you want to proceed with content updates? (y/n)" -ForegroundColor Yellow
$selector=read-host 

if ($selector -match "y"){
    write-host "checking for content updates..." -ForegroundColor White
    Invoke-panXMLapi -Type "op" -cmd "<request><content><upgrade><check></check></upgrade></content></request>" -Pan1 $pan1
    write-host "downloading content updates..." -ForegroundColor White
    Invoke-panXMLapi -Type "op" -cmd "<request><content><upgrade><download><latest></latest></download></upgrade></content></request>" -Pan1 $pan1
    write-host "installing content updates..." -ForegroundColor White
    Invoke-panXMLapi -Type "op" -cmd "<request><content><upgrade><install><version>latest</version></install></upgrade></content></request>" -Pan1 $pan1
}

# 3- DOWNLOAD PANOS TARGET VERSION & INSTALL
write-host "do you want to perform PanOS upgrade? (y/n)" -ForegroundColor yellow
$selector=read-host

if ($selector -match "y"){
    write-host "checking for software updates..." -ForegroundColor White
    Invoke-panXMLapi -Type "op" -cmd "<request><system><software><check></check></software></system></request>" -Pan1 $pan1
    
    write-host "What version of PanOS do you want to install? eg. `"10.1.4-h4`"" -ForegroundColor Yellow
    $panOStargetversion=read-host
    write-host "downloading PanOS $panOStargetversion..." -ForegroundColor White
    Invoke-panXMLapi -Type "op" -cmd "<request><system><software><download><version>$panOStargetversion</version></download></software></system></request>" -Pan1 $pan1

    write-host "do you want to backup PanOS config? (y/n)" -ForegroundColor Yellow
    $selector=read-host
    if ($selector -match "y"){
        $configBackup="upgrade_$((get-date).ToString('%M.%d.%y-%H%m%s')).xml"
        write-host "saving candidate PAN config on firewall and locally: $configBackup" -ForegroundColor White
        Invoke-panXMLapi -Type "op" -cmd "<save><config><to>$configBackup</to></config></save>" -Pan1 $pan1
        Invoke-panXMLapi -Type "export" -category "configuration" -pan1 $pan1 -ExportFile $configBackup
    }
    
    write-host "ready to install $panOStargetversion." -ForegroundColor Yellow
    write-host "Are you sure you want to install and reboot immediately after upgrade is complete? (y/n)"
    $selector=Read-Host
    if ($selector -match "y"){
        # do the upgrade and reboot here.
        write-host "installing $panOStargetversion..." -ForegroundColor Yellow
        Invoke-panXMLapi -Type "op" -cmd "<request><system><software><install><version>$panOStargetversion</version></install></software></system></request>" -Pan1 $pan1
        write-host "rebooting $pan1 ..." -ForegroundColor Yellow
        Invoke-panXMLapi -Type "op" -cmd "<request><restart><system></system></restart></request>" -Pan1 $pan1
    }
}
write-host "done!" -ForegroundColor DarkYellow


#$credSRC=Get-Credential -Message "Please enter a valid user/password with API access to your SOURCE Pan device"
#$panHostSRC=read-host "Please enter the address of your source Panorama"
#Get-LocalOS



#(Invoke-RestMethod @certValidation -Uri "https://$panHostSRC/api/?type=keygen&user=$($credSRC.userName)&password=$($credSRC.GetNetworkCredential().password)" -Method post).response.result.key  
 
