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

function Get-PANcred {
    [Parameter(ValueFromPipeline = $true)]
    $script:cred1=Get-Credential -Message "Please enter a valid user/password with API access to your PAN device : $pan1"
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
        $global:headers1=@{'X-PAN-KEY' = $key1}
        #$global:headers1.Add("Content-Type", "application/json")
        $global:panOSversion1=(((Invoke-RestMethod @certvalidation -Uri "https://$pan1/api/?type=version&key=$($key1)" -Method post).response.result."sw-version").split('.')[0,1] -join '.')
        if ($panOSversion1 -notlike "9.0"){
            $global:panOSversion1= "v" + $panOSversion1
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
                $apiResult=Invoke-RestMethod @certvalidation -Uri "https://$pan1/api/`?type`=$type$category$action$cmd$xpath" -Headers $headers1
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

