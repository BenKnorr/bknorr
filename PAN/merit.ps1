## test file to check module functionality! ##

###########
##########
#########
########
#######
######
#####

################
################

$global:headers1=@{}
$global:panosversion1=""

function Get-LocalOS {
    ###> this function is to bypass certificate validation since many newly configured PAN devices do not have proper certs yet.

    $localENV=get-childitem -path env:
    $script:certValidation=@{}

    ###> this first block is for Windows PCs 
    if ($localENV | Where-Object {($_.name -like "OS") -and  ($_.value -match "Windows")}){
        # this is a windows host
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
    else{
        ###> assuming mac or linux host (mac does not have any "OS" property in env)
        $script:certValidation=@{SkipCertificateCheck=$true}
    }
}

function Get-PanAPIkey {
    ###> this function gets the API key, sets up headers that will be used in query-PAN
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        #[SecureString] $cred1,
        [String[]]$pan1
    )
    Get-LocalOS
    $cred1=Get-Credential -Message "Please enter a valid user/password with API access to your PAN device : $pan1"
    #Get-PANcred($pan1)
    try {
        $global:key1=(Invoke-RestMethod @certvalidation -Uri "https://$pan1/api/?type=keygen&user=$($cred1.userName)&password=$($cred1.GetNetworkCredential().password)" -Method post).response.result.key
        # $global:headers1=@{'X-PAN-KEY' = $key1}
        # $global:headers1.Add("Content-Type", "application/json")
        
        $get=(Invoke-RestMethod @certvalidation -Uri "https://$pan1/api/?type=version&key=$($key1)" -Method post).response.result
        
        $global:panOSversion1=($get)."sw-version".split('.')[0,1] -join '.'
        if ($panOSversion1 -notlike "9.0"){
            $global:panOSversion1= "v" + $panOSversion1
        }

        $panorama=@('M-100','M-300','M-500','panorama','Panorama')
        if ($panorama -notcontains $get.model){
            write-host "ALERT : this script is designed for use with Panorama. Your model is `'$($get.model)`'" -ForegroundColor Red
        }

        write-host "SUCCESS : good hostname and credential." -ForegroundColor Green
    }
    catch {
        write-host "FAIL : something didn't work. bye!"
        write-host $error[0] -ForegroundColor Red
        $error.clear()
        break
    }
}

function Invoke-panXMLapi {
    ###> this is used for XML API requests
    ### https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-panorama-api/about-the-pan-os-xml-api/structure-of-a-pan-os-xml-api-request.html#id93d1e502-4e90-414f-8179-c135811f3c28
    
    [CmdletBinding()]
        param(
            [Parameter(ValueFromPipeline = $true)]
            [String[]]$Type,        ## config, export, import, commit, op, etc.
            [String[]]$Action,      ## get (read candidate), set , edit , delete, etc.
            [String[]]$cmd,         ## used if type is "op"
            [String[]]$category,    
            #[String[]]$Headers1,
            [String[]]$Pan1,
            [String[]]$xPath,
            [String[]]$ExportFile
        )
 
    if (!($null -eq $cmd)){$cmd="&cmd=" + "$cmd"}
    if (!($null -eq $xpath)){$xpath="&xpath=" + "$xpath"}
    if (!($null -eq $action)){$action="&action=" + "$action"}
    if (!($null -eq $category)){$category="&category=" + "$category"}

    try{
        
        if ($null -ne $ExportFile){
            ## this is only used if a file/result is going to be exported.
            [xml]$apiResult=""
        }
        else {}

        $apiResult=Invoke-RestMethod @certvalidation -Uri "https://$pan1/api/?type=$type$category$action$cmd$xpath" -Headers $headers1 -ErrorAction Stop
        if ($apiResult.response.code -match "[20-19]"){
            ##19 or 20 are successful api status when a job is successfully queued.
            $cmd="&cmd=<show><jobs><id>$($apiResult.response.result.job)</id></jobs></show>"
            do{
                $apiResult=Invoke-RestMethod @certvalidation -Uri "https://$pan1/api/?type=$type$category$action$cmd$xpath" -Headers $headers1
                sleep 2
                write-host "Checking job ($($apiResult.response.result.job.id))....$($apiResult.response.result.job.progress)%"
            }
            until ($apiResult.response.result.job.status -eq "FIN")
            write-host "Job $($apiResult.response.result.job.id) complete."
        }
        elseif ($null -ne $ExportFile){
            ## saving an export if $exportfile is defined
            $apiresult.save($ExportFile)
            write-host "saved $ExportFile successfully."
        }
        elseif (($null -eq $apiResult.response.code) -and ($apiResult.response.status -like "success")){
            write-host "success on $cmd"
        }
        else{
            write-host "something else happened with $cmd .... probably should stop here...."
        }
    }

    catch{
        write-host "failed on $obj_name" -ForegroundColor red
        write-host $error[0] -ForegroundColor red
    } 
    
}

##################### queryPan is what will interact with restAPI. This isn't designed to work with non panorama devices yet.
function Invoke-panAPI {
    ## this should include api get
    [CmdletBinding()]
        param(
            [Parameter(ValueFromPipeline = $true)]
            [String[]]$APIargs,
            [String[]]$Method,
            $Body,
            [String[]]$objPath,
            [String[]]$obj_name,
            [String[]]$panOSversion,
            [String[]]$Pan1#,
            #[String[]]$headers
        )
    Clear-Variable restResult -scope global -ErrorAction SilentlyContinue
    $headersREST=@{"X-PAN-KEY" = "$key1"}
    $headersREST.add("Content-Type" , "application/json")
    try{
        $global:restResult=Invoke-RestMethod @certvalidation -Uri "https://$pan1/restapi/$panOSversion1/$objPath`?$apiargs" -Headers $headersREST -Method $Method -Body $Body
        write-host "SUCCESS : on $objPath" -ForegroundColor Green
    }
    catch{
        write-host "FAILED : on $objPath" -ForegroundColor red
        write-host $error[0] -ForegroundColor red
        Clear-Variable restResult -Scope global
    }
}

function processRule{
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [String[]]$APIargs,
        [String[]]$Method,
        $Body,
        [String[]]$objPath,
        [String[]]$obj_name,
        [String[]]$panOSversion,
        [String[]]$Pan1,
        [String[]]$externalZone
    )

    $headersREST=@{"X-PAN-KEY" = "$key1"}
    $headersREST.add("Content-Type" , "application/json")

    $body.entry.psobject.Properties.Remove('@uuid')
    $body.entry.psobject.Properties.Remove('@location')
    $body.entry.psobject.Properties.Remove('@device-group')
    $body.entry.psobject.Properties.Remove('@loc')
    
    $body=$body |ConvertTo-Json -Depth 99

    try{
        Invoke-RestMethod @certvalidation -Uri "https://$pan1/restapi/$panOSversion1/$objPath`?$apiargs" -Headers $headersREST -Method $Method -Body $Body
        write-host "SUCCESS : on $objPath" -ForegroundColor Green
    }
    catch{
        write-host "FAILED : on $objPath" -ForegroundColor red
        write-host $error[0] -ForegroundColor red
        Clear-Variable restResult -Scope global
    }


}
function script:Set-PANsecurityProfile_onRule {
# this is going to set profiles in a security rule.

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [String[]]$trafficdirection,
        [String[]]$mode,
        [String[]]$securityprofile,
        [String[]]$tag,
        [String[]]$body
    )

    ## >> TAG 
    if ($null -eq $script:body.entry.tag){
        #only add noteproperty for tag if it doesn't exist.
        $script:body.entry | Add-Member -MemberType NoteProperty -Name "tag" -Value @{} -Force
        $script:body.entry.tag=[PScustomobject]@{member=@($tag)}
    }
    elseif ($null -eq $script:body.entry.tag.member){
        # for reasons unknown, Palo sometimes adds tag property without a member within it. We create it and populate here.
        $script:body.entry.tag=[PScustomobject]@{member=@($tag)}
    }
    elseif ($script:body.entry.tag.member -match "$tag"){
        #tag already added
    }
    else{
        # add the tag to the rest of the tags.
        $script:body.entry.tag.member=$script:body.entry.tag.member+($tag)
    }
    ## << TAG 

    if ($mode -match "alert"){
        $securityprofile="Alert-Only"
    }

    ## PROFILE SETTINGS
    if ($null -eq $script:body.entry.'profile-setting'){
        ## we hit this if there is NO PROFILE SETTING WHATSOEVER. we handle alert-only and enforce modes.
        $script:body.entry | Add-Member -MemberType NoteProperty -Name "profile-setting" -Value @{} -Force
        $script:body.entry.'profile-setting'=[PScustomobject]@{group=[PScustomobject]@{member=@($securityprofile)}}
    }
    elseif ($script:body.entry.'profile-setting'.group.member -eq $securityprofile){
        ## security profile group profile already addded : we dont' do anything here.
    }
    elseif ($mode -eq "enforce"){
        $script:body.entry.'profile-setting'=[PScustomobject]@{group=[PScustomobject]@{member=@($securityprofile)}}
    }
    elseif (($null -ne $script:body.entry.'profile-setting'.profiles) -and ($mode -eq "alert")){
        ## this section should only hit if there is a profile or multiple profiles (no group) and mode is alert.
        $AVprofile="Alert-Only-AV"
        $ASprofile="Alert-Only-AS"
        $VPprofile="Alert-Only-VP"
        $URLprofile="Alert-Only-URL"
        $FBprofile="Alert-Only-FB"
        $WFprofile="Alert-Only-WF"
        if ($null -eq $script:body.entry.'profile-setting'.profiles.virus){
            #set the AV profile to alert : there was no profile here. we always go to alert first
            $script:body.entry.'profile-setting'.profiles | Add-Member -MemberType NoteProperty -Name "virus" -Value @{} -Force
            $script:body.entry.'profile-setting'.profiles.virus=[PScustomobject]@{member=@($AVprofile)}
        }
        if ($null -eq $script:body.entry.'profile-setting'.profiles.spyware){
            #set the AS profile to alert : there was no profile here. we always go to alert first
            $script:body.entry.'profile-setting'.profiles | Add-Member -MemberType NoteProperty -Name "spyware" -Value @{} -Force
            $script:body.entry.'profile-setting'.profiles.spyware=[PScustomobject]@{member=@($ASprofile)}
        }            
        if ($null -eq $script:body.entry.'profile-setting'.profiles.'url-filtering'){
            #set the URL profile to alert : there was no profile here. we always go to alert first
            $script:body.entry.'profile-setting'.profiles | Add-Member -MemberType NoteProperty -Name "url-filtering" -Value @{} -Force
            $script:body.entry.'profile-setting'.profiles.'url-filtering'=[PScustomobject]@{member=@($URLprofile)}
        }
        if ($null -eq $script:body.entry.'profile-setting'.profiles.'file-blocking'){
            #set the FB profile to alert : there was no profile here. we always go to alert first
            $script:body.entry.'profile-setting'.profiles | Add-Member -MemberType NoteProperty -Name "file-blocking" -Value @{} -Force
            $script:body.entry.'profile-setting'.profiles.'file-blocking'=[PScustomobject]@{member=@($FBprofile)}
        }
        if ($null -eq $script:body.entry.'profile-setting'.profiles.vulnerability){
            #set the VP profile to alert : there was no profile here. we always go to alert first
            $script:body.entry.'profile-setting'.profiles | Add-Member -MemberType NoteProperty -Name "vulnerability" -Value @{} -Force
            $script:body.entry.'profile-setting'.profiles.vulnerability=[PScustomobject]@{member=@($VPprofile)}
        }
        if ($null -eq $script:body.entry.'profile-setting'.profiles.'wildfire-analysis'){
            #set the WF profile to alert : there was no profile here. we always go to alert first
            $script:body.entry.'profile-setting'.profiles | Add-Member -MemberType NoteProperty -Name "wildfire-analysis" -Value @{} -Force
            $script:body.entry.'profile-setting'.profiles.'wildfire-analysis'=[PScustomobject]@{member=@($WFprofile)}
        }
    }
    elseif (($null -ne $script:body.entry.group) -and ($script:body.entry.group.member -ne $securityprofile) -and ($mode -eq "alert")){
        ## nothing to do here: mode is alert and a group is already defined.
    }

## end of function
}

##############################################################
## required params that need to be gathered in this script
## $pan1 , $cred1 , $pan2 , $cred2
##############################################################

write-host " What is your IP or hostname of PAN that you want to work with? : " -ForegroundColor yellow -NoNewline
$pan1=Read-Host
Get-PanAPIkey -pan1 $pan1

## CUSTOMER STUFF >>  ###
write-host "INFO : this iteration of the script will modify security policies to attach to previously updated security profiles." -ForegroundColor darkyellow
## << CUSTOMER STUFF  ###

#get devicegroups...
Invoke-panAPI -Method get -panOSversion $panosversion1 -Pan1 $pan1 -objPath 'Panorama/DeviceGroups'
$restResult.result.entry.'@name'
write-host " Please enter a device-group to work with (or `'shared`') : " -ForegroundColor yellow -NoNewline
$dg=Read-Host

#get templates that are associated with DG...
Invoke-panAPI -Method get -panOSversion $panosversion1 -Pan1 $pan1 -objPath 'Panorama/Templates'
$restResult.result.entry.'@name'
write-host " Please enter a template that contains the zones associated with your target firewalls? : " -ForegroundColor yellow -NoNewline
$template=Read-Host

#get zones to define external...
Invoke-panAPI -Method get -panOSversion $panosversion1 -Pan1 $pan1 -objPath 'Network/Zones' -APIargs "location=template&template=$template&vsys=vsys1"
$restResult.result.entry.'@name'
write-host " Please enter your outside zone : " -ForegroundColor yellow -NoNewline
$outsideZone=read-host

#get answer for security profiles...
write-host " Do you want to set unset security profiles to alert-only, or set all security profiles to full enforcement? (`'alert`'/`'enforce`') : " -ForegroundColor yellow -NoNewline
$securityProfileAction=read-host


#process security rules
# this assumes the names of the security profile groups are using naming syntax from iron skillet baselines
# tags are added for every rule that is processed : internal, outbound, inbound
# "alert-only" security profile group is defined within the Set-PANsecurityProfile_onRule function.
$profileGroupOutbound='Outbound'
$profileGroupInbound='Inbound'
$profileGroupInternal='Internal'
$tagOutbound='Outbound'
$tagInbound='Inbound'
$tagInternal='Internal'

##############
##############
## the loop where we do work >>
##############

foreach ($prepost in @("Policies/SecurityPreRules","Policies/SecurityPostRules")){
    if ($dg -match 'shared'){
        Invoke-panAPI -Method get -panOSversion $panosversion1 -Pan1 $pan1 -objPath $prepost -APIargs "location=shared"
        foreach ($rule in ($restResult.result.entry |Where-Object {($_.action -like 'allow')})){
            if ($rule.to.member -contains $outsideZone){
                #outbound

                write-host "OUTBOUND : $($rule.'@name') , $($rule.from.member) to $($rule.to.member)" -ForegroundColor Cyan
                $script:body=[pscustomobject]@{entry=$rule}

                Set-PANsecurityProfile_onRule -body $script:body -mode $securityProfileAction -trafficdirection "outbound" -securityprofile $profileGroupOutbound -tag $tagOutbound
                processRule -Method put -objPath $prepost -panOSversion $panosversion1 -Pan1 $pan1 -APIargs "location=shared&name=$($rule.'@name')" -body $script:body
            }
            elseif ($rule.from.member -contains $outsideZone){
                # inbound
                write-host "INBOUND : $($rule.'@name') , $($rule.from.member) to $($rule.to.member)" -ForegroundColor Red
                $script:body=[pscustomobject]@{entry=$rule}

                Set-PANsecurityProfile_onRule -body $script:body -mode $securityProfileAction -trafficdirection "inbound" -securityprofile $profileGroupInbound -tag $tagInbound
                processRule -Method put -objPath $prepost -panOSversion $panosversion1 -Pan1 $pan1 -APIargs "location=shared&name=$($rule.'@name')" -body $script:body
            }
            else{
                # internal
                write-host "INTERNAL : $($rule.'@name') , $($rule.from.member) to $($rule.to.member)" -ForegroundColor DarkYellow
                $script:body=[pscustomobject]@{entry=$rule}

                Set-PANsecurityProfile_onRule -body $script:body -mode $securityProfileAction -trafficdirection "internal" -securityprofile $profileGroupInternal -tag $tagInternal
                processRule -Method put -objPath $prepost -panOSversion $panosversion1 -Pan1 $pan1 -APIargs "location=shared&name=$($rule.'@name')" -body $script:body
            }
        }
    }
    else {
        Invoke-panAPI -Method get -panOSversion $panosversion1 -Pan1 $pan1 -objPath $prepost -APIargs "location=device-group&device-group=$dg"
        foreach ($rule in ($restResult.result.entry |Where-Object {($_.action -like 'allow')})){
            if ($rule.to.member -contains $outsideZone){
                #outbound

                write-host "OUTBOUND : $($rule.'@name') , $($rule.from.member) to $($rule.to.member)" -ForegroundColor Cyan
                $script:body=[pscustomobject]@{entry=$rule}

                Set-PANsecurityProfile_onRule -body $script:body -mode $securityProfileAction -trafficdirection "outbound" -securityprofile $profileGroupOutbound -tag $tagOutbound
                processRule -Method put -objPath $prepost -panOSversion $panosversion1 -Pan1 $pan1 -APIargs "location=device-group&device-group=$dg&name=$($rule.'@name')" -body $script:body
            }
            elseif ($rule.from.member -contains $outsideZone){
                # inbound
                write-host "INBOUND : $($rule.'@name') , $($rule.from.member) to $($rule.to.member)" -ForegroundColor Red
                $script:body=[pscustomobject]@{entry=$rule}

                Set-PANsecurityProfile_onRule -body $script:body -mode $securityProfileAction -trafficdirection "inbound" -securityprofile $profileGroupInbound -tag $tagInbound
                processRule -Method put -objPath $prepost -panOSversion $panosversion1 -Pan1 $pan1 -APIargs "location=device-group&device-group=$dg&name=$($rule.'@name')" -body $script:body
            }
            else{
                # internal
                write-host "INTERNAL : $($rule.'@name') , $($rule.from.member) to $($rule.to.member)" -ForegroundColor DarkYellow
                $script:body=[pscustomobject]@{entry=$rule}

                Set-PANsecurityProfile_onRule -body $script:body -mode $securityProfileAction -trafficdirection "internal" -securityprofile $profileGroupInternal -tag $tagInternal
                processRule -Method put -objPath $prepost -panOSversion $panosversion1 -Pan1 $pan1 -APIargs "location=device-group&device-group=$dg&name=$($rule.'@name')" -body $script:body
            }
        }
    }
} 