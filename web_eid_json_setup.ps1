Set-Location app
$mypath = Get-Location
$jsonName = "\webeidPython.json"
$batName = "\webeidPython.bat"

$jsonPath = $mypath.toString()+$jsonName
$batPath = $mypath.toString()+$batName

Write-Output "Path of the json : $jsonPath"
Write-Output "Path of the bat : $batPath"

$jsonObject = Get-Content $jsonPath -raw | ConvertFrom-Json

#Replace json content
$jsonObject.path = $batPath
$jsonObject | ConvertTo-Json | set-content $jsonPath

Set-Location ..
Write-Output "Success! Check in $jsonPath the value for 'path' key is """$batPath"""" 