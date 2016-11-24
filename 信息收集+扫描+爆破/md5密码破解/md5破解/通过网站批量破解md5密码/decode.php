<?php
print_r(" 
  +----------------------------------------------------------------------+ 
  |                Decode     MD5    From    www.xmd5.org                |
  |                            By Lovesuae                               |
  |                       h4ckj0y_at_gmail.com                           |
  |                用法：       decode.exe md5.txt                       | 
  |                记数点保存在counter.txt中,如果必要请清零              |
  +----------------------------------------------------------------------+ 
"); 

ini_set("max_execution_time",0); 
error_reporting(7); 
global $contents,$filename,$id,$beginid;
$filename="$argv[1]"; 
$id=1;//计数点
if (!strpos($filename,".")) exit;

main($filename,readcounter());


function main($filename,$beginid)
{
	global $contents,$filename,$id;
	openfile($filename);
	$handle = @fopen("$filename", "r");
	checktest();
	if ($handle) {
	   while (!feof($handle)) {
		   $buffer = fgets($handle, 128);
		   $buffer = preg_replace('/\r|\n/', '', $buffer); 
		   if (strlen($buffer) == 16 or strlen($buffer) == 32)
			{
				if ($id>=$beginid){
					echo ">正在破解散列".$id."：".$buffer."\r\n";
					decode($buffer,$contents);	
					if (!($id%5)){
						checktest();
						writefile($filename);
						setcounter($filename,$id);
					}
				}
			}
			$id=$id+1;
	   }
	fclose($handle);
	}		
}

function decode($hash,$contents){
	$fp = fsockopen('125.91.8.135',80);
	$out = "GET /md5/md5check.asp?md5pass=$hash HTTP/1.1\r\n";
	$out .= "Accept: */*\r\n";
	$out .= "Referer: http://www.xmd5.org/\r\n";
	$out .= "Accept-Language: zh-cn\r\n";
	$out .= "UA-CPU: x86\r\n";
	$out .= "Accept-Encoding: gzip, deflate\r\n";
	$out .= "User-Agent: Mozilla/4.0\r\n";
	$out .= "Host:www.xmd5.org:80\r\n";
	$out .= "Connection: Close\r\n";
	$out .= "Cookie: \r\n\r\n";
	fwrite($fp, $out);
	$fr= fread($fp,8096);
	$beg=strpos($fr,'Location:');
	$end=strpos($fr,'Server:');
	$result=substr($fr,$beg+51,$end-$beg-53);
	if (strlen($result)<=15){
		if ($result=="no") {
			echo ">.无法破解\r\n\r\n";}
		else {
			echo ">.已破解: $result\r\n\r\n";
			replace($hash,$result,$contents);}
	}
	else {
		echo "\r\n发现错误，建议重新拨号后再试！！！！\r\n";
		exit;
	}
	fclose($fp);
}

function checktest(){
	global $contents,$filename;
	$hash="CCA9F141BD0DA3496C3FA6AB3E31ADD3";
	$fp = fsockopen('125.91.8.135',80);
	$out = "GET /md5/md5check.asp?md5pass=$hash HTTP/1.1\r\n";
	$out .= "Accept: */*\r\n";
	$out .= "Referer: http://www.xmd5.org/\r\n";
	$out .= "Accept-Language: zh-cn\r\n";
	$out .= "UA-CPU: x86\r\n";
	$out .= "Accept-Encoding: gzip, deflate\r\n";
	$out .= "User-Agent: Mozilla/4.0\r\n";
	$out .= "Host:www.xmd5.org:80\r\n";
	$out .= "Connection: Close\r\n";
	$out .= "Cookie: \r\n\r\n";
	fwrite($fp, $out);
	$fr= fread($fp,4068);
	$beg=strpos($fr,'Location:');
	$end=strpos($fr,'Server:');
	$result=substr($fr,$beg+51,$end-$beg-53);
	if ($result!="no") {
		echo "当前网站无法正常破解，建议重新拨号后再试！\r\n";
		exit;
	}
}

function replace($hash,$result,$contents)
{
	global $contents,$filename;
	$contents=str_replace($hash,$result,$contents);
}

function openfile($filename)
{
	global $contents,$filename;
	$contents = file_get_contents($filename);
}

function writefile($filename)
{
	global $contents;
	$handle = @fopen($filename, "w+");
	if (fwrite($handle,$contents)) {
		//echo "写入文件成功！\r\n";
	}
	else {
		echo "写入文件失败！\r\n";
		exit;}
	fclose($handle);
}

function setcounter($filename,$id){
	global $beginid,$id;
	$fn="counter.txt";
	$handle = @fopen($fn, "w+");
	if (fwrite($handle,$id)) {
		//echo "写入记录点成功！\r\n\r\n";
		}
	else {
		echo "写入记录点失败！\r\n\r\n";
		exit;}
	fclose($handle);
}
function readcounter(){
	global $beginid,$id;
	$fn="counter.txt";
	$handle2 = @fopen($fn, "a+");
	$beginid = fgets($handle2, 128);
	if ($beginid) {
		echo "\r\n>记录点读取成功\r\n\r\n";}
	else $beginid=1;
	return $beginid;
}
?>
