## get keys and set up headers
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("Content-Type", "application/json")
$accessKey=Read-Host "Please enter your a tenable admin user API accessKey"
$secretKey=Read-host "Plesse enter your a tenable admin user API secretKey"
$headers.Add("X-ApiKeys", "accessKey=$accessKey;secretKey=$secretKey")

write-host "this is set up to bulk add Tag values based on information in an existing .csv file when interacting with the Tenable API today"

write-host "fields expected in the .csv file are `"network`" `"location`" and `"description`""-ForegroundColor yellow
$data=read-host "please enter a full or relative path to your .csv file that meets these critera"
$data=import-csv $data
$category=read-host "what is the name of your Tag category (case sensitive)?"

foreach ($line in ($data | group {$_.location})){
    #create json for this line's data to post up to tenable tag value
    $jsonargs=@{filters=@{asset=@{or=@()}}}
    $jsonargs.category_name="$category"
    $jsonargs.description="$($line.group[0].description)"
    $jsonargs.value="$($line.group[0].location)"
    foreach ($value in $line.group){
        $ipv4args=@{
            field="ipv4"
            operator="eq"
            value="$($value.network)"
        }
        $jsonargs.filters.asset.or+=$ipv4args
    }
    $jsonargs=$jsonargs |convertto-json -Depth 99

   Invoke-RestMethod -Uri https://cloud.tenable.com/tags/values -Headers $headers -Method post -Body $jsonargs 
   write-host "sleeping for 2 seconds..."
   sleep 2
}
