##############################################################
###                                                        ###
###   Active Directory Certificate Template ACL reporter   ###
###                                                        ###
###   This script parses the default PKI container in      ###
###   AD and records ACLs of all certificate templates.    ###
###   A log file is generated on the current user's        ###
###   desktop with servername, domain, and date in the     ###
###   filename. In addition, this script creates a second  ###
###   file on the desktop that contains details of         ### 
###   individual certificate templates.                    ###
###                                                        ###
###   Domain Admin or equivalent access is required to     ###
###   to reliably use this script.                         ###
###                                                        ###
###                                                        ###
###                                                        ###
###                                                        ###
###                                                        ###
###   written by Ben Knorr                                 ###
###   bknorr@compunet.biz                                  ###
###                                                        ###
###                                                        ###
###   Please use this script cautiously!                   ###
###   v0.6.1 last modified 7.10.2019                       ###
###                                                        ###
##############################################################

### PSPKI MODULE IS REQUIRED SINCE v0.4 

clear
$confirmation=Read-Host "You should be running this script as a user of the Domain Admins or Enterprise Admins group. Continue? (y/n)"
if (($confirmation -eq 'y') -or ($confirmation -eq 'Y'))
{}
else
{
    exit
}


try
{
    write-host "trying to import PSPKI module..."
    Import-Module pspki -ErrorAction stop
    write-host "success!"
}
catch
{
    write-host "`r`n...PSPKI module is not installed."
    $confirmation=Read-Host "The PSPKI module is required for this script to complete. Install it now from internet repository? (y/n)"
    if (($confirmation -eq 'y') -or ($confirmation -eq 'Y'))
    {
        $confirmation=Read-Host "`r`nYou must be running this powershell console as an elevated user; if you aren't using a privileged session, unexpected results may occur. Continue? (y/n)"
        if (($confirmation -eq 'y') -or ($confirmation -eq 'Y'))
        {
            write-host "`r`nInstalling pspki from internet. Please confirm additional prompts when requested."
            try
            {
                install-module pspki -ErrorAction stop
            }
            catch
            {
                write-host "`r`n$_" -ForegroundColor Red
                exit
            }

            try 
            {
                import-module pspki -ErrorAction stop
            }
            catch
            {
                write-host "something didn't work and pspki couldn't be installed. Sorry, I'm a computer."
                exit
            }
        }
        else
        {
            exit
        }

    }
    else 
    {
        exit
    }
    
}
$TemplateACLFileName="$env:USERPROFILE\desktop\CertificateTemplateACL_export-$($env:computername).$($env:userdnsdomain)-$(get-date -format "yyyy-MM-dd-hhmmss").csv"
$ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
$ConfigContext = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"
$ds = New-object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$ConfigContext","objectClass=pKICertificateTemplate")
$templates = $ds.findall().GetDirectoryEntry() | %{$_}
$allTemplateACLs=@()

write-host "Processing ACLs..."
sleep 1
foreach ($template in $templates)
{
    write-host "`t" $template.cn
    foreach ($current in $template.ObjectSecurity.Access)
    {
            $Rights = @($current.ActiveDirectoryRights.ToString().Split(",",[StringSplitOptions]::RemoveEmptyEntries) | %{$_.trim()})
            $GUID = $current.ObjectType.ToString()
            $current | Add-Member -Name Permission -MemberType NoteProperty -Value @()
            if ($Rights -contains "GenericRead") {$current.Permission += "Read"}
            if ($Rights -contains "WriteDacl") {$current.Permission += "Write"}
            if ($Rights -contains "GenericAll") {$current.Permission += "Full Control"}
            if ($Rights -contains "ReadProperty") {$current.Permission += "Read"}
            if ($Rights -contains "ExtendedRight") {
                if ($GUID -eq "a05b8cc2-17bc-4802-a710-e7c15ab866a2") {$current.Permission += "Autoenroll"}
                elseif ($GUID -eq "0e10c968-78fb-11d2-90d4-00c04f79dc55") {$current.Permission += "Enroll"}
            }
            
            $ACLs=[ordered]@{}
            $ACLs.CN="$($template.cn)"
            $ACLs.DistinguishedName="$($template.distinguishedName)"
            $ACLs.Permission="$($current.Permission -join ',')"
            $ACLs.ActiveDirectoryRights=$current.ActiveDirectoryRights
            $ACLs.IdentityReference=$current.IdentityReference
            $ACLs.InheritanceType=$current.InheritanceType
            $ACLs.ObjectType=$current.ObjectType
            $ACLs.InheritedObjectType=$current.InheritedObjectType
            $ACLs.ObjectFlags=$current.ObjectFlags
            $ACLs.AccessControlType=$current.AccessControlType
            $ACLs.IsInherited=$current.IsInherited
            $ACLs.InheritanceFlags=$current.InheritanceFlags
            $ACLs.PropagationFlags=$current.PropagationFlags
            $allTemplateACLs+=New-Object psobject -Property $ACLs
    }
}
# write ACLs to file
$allTemplateACLs | Export-Csv $TemplateACLFileName -Delimiter "," -Encoding UTF8 -NoTypeInformation

#write certificate template details to file
write-host "`r`nGathering certificate template details and saving to file..."
sleep 1
$TemplateDescriptionFileName="$env:USERPROFILE\desktop\CertificateTemplateDescriptions_export-$($env:computername).$($env:userdnsdomain)-$(get-date -format "yyyy-MM-dd-hhmmss").log"
$templates=Get-CertificateTemplate
Add-Content $env:USERNAME -path $TemplateDescriptionFileName
Add-Content $env:computername -path $TemplateDescriptionFileName
Add-Content $env:userdnsdomain -path $TemplateDescriptionFileName
Add-Content $(get-date) -path $TemplateDescriptionFileName

foreach ($template in $templates)
{
    Add-Content "`r`n######################################################################################################################################################" -path $TemplateDescriptionFileName
    add-content "Template: $($template.displayName)" -path $TemplateDescriptionFileName
    add-content "AutoEnroll enabled: $($template.AutoenrollmentAllowed)" -path $TemplateDescriptionFileName
    $template.settings | out-string | add-content -path $TemplateDescriptionFileName
}
write-host "wrote $TemplateACLFileName"
write-host "wrote $TemplateDescriptionFileName"
write-host "`r`n The information in these logfiles is informational and does not contain private cryptographic information.`n Please send results via email to bknorr@compunet.biz."