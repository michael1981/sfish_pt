<#
.SYNOPSIS
Nishang Payload in Kautilya to convert an executable to text file.

.DESCRIPTION
This payload converts and an executable to a text file.

.PARAMETER EXE
The executable to be converted.

.PARAMETER FileName
Name of the text file to which executable will be converted.

.EXAMPLE
PS > ExetoText evil.exe evil.txt

.LINK
http://www.exploit-monday.com/2011/09/dropping-executables-with-powershell.html
https://github.com/samratashok/nishang
https://github.com/samratashok/Kautilya
#>


function ExetoText
{
    [CmdletBinding()] Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $EXE, 
        
        [Parameter(Position = 1, Mandatory = $True)]
        [String]
        $Filename
    )
    [byte[]] $hexdump = get-content -encoding byte -path "$EXE"
    [System.IO.File]::WriteAllLines("$Filename", ([string]$hexdump))
}
