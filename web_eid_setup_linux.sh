#!/bin/bash
cd app
jsonName='webeidPython.json' 
appName='webeidPython.py'  

jsonPath="$PWD"/"$( basename "$jsonName" )"
export appPath="$PWD"/"$( basename "$appName")"

content=$(jq ".path=\"$appPath\"" $jsonPath)
echo $content > $jsonPath

mozillaNativeHostPath="/usr/lib/mozilla/native-messaging-hosts"

cp $jsonPath $mozillaNativeHostPath
echo "Sucessfully copied $jsonPath in $mozillaNativeHostPath"
echo "Check that the content of the \"path\" value in the json file matches 
the full path to /app/$appName"
cd ..
