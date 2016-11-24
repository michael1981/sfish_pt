<?php
$shell = new COM("WScript.Shell") or die("This thing requires Windows Scripting Host");
$rootkey = "HKEY_LOCAL_MACHINE\\SYSTEM\RAdmin\\v2.0\\Server\\Parameters\\";
$Parameter = "Parameter";
$Port = "Port";
$logpath = "LogFilePath";
$myparam = $shell->RegRead($rootkey.$Parameter);
$myport = $shell->RegRead($rootkey.$Port);
$path = $shell->RegRead($rootkey.$logpath);
echo "radmin hash is:";
foreach($myparam as $a){
echo dechex($a);
}
echo "<br>";
echo "radmin port is :".hexdec(dechex($myport[1]).dechex($myport[0]))."<br>";
echo "radmin log path is:$path<br>";
echo "please clean the log"
?>
