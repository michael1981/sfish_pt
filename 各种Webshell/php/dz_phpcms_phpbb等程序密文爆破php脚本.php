<?php
set_time_limit(0);
/*----------------参数选择部分-----------------*/
switch($argv[1])
{
	case 1://测试模块1
	test_1($argv[2]);
	break;
	case 2://测试模块2
	test_2();
	break;
	case 3://测试模块3
	test_3();
	break;
	default:
	print_r('
-------------------------------------------
title: md5(md5($pass).$salt)批量暴力测试工具
Author: L.N.
Version: 1.0.0
Author_URL:http://lanu.sinaapp.com
Description: 
 暴力测试工具分为3个模块：
   1.指定密码测试;
   2.以用户位密码测试;
   3.以用户秘密吗和随机数测试;
 字典文件：[放在和脚本同目录下]
	salt.txt
	pass.txt
	user.txt
	rand.txt
Example:
  php '.$argv[0].' 选择模块 [指定密码]
  php '.$argv[0].' 1 1234567890
  php '.$argv[0].' 2
  php '.$argv[0].' 3
-----------------------------------------
');
    die;
}

/*----------------测试模块定义部分-----------------*/

/*
* 测试模块1
* 指定测试密码
*/
function test_1($password)
{
	echo "开始测试密码\n--------------------------------------\n";
	$file1_name = fopen("salt.txt","r");//打开salt
	while(!feof($file1_name))//循环salt
  	{
     	$salt=trim(fgets($file1_name));//读取salt
     	$file_name = fopen("pass.txt","r");//打开pass
     	$ii=1;
     	while(!feof($file_name))//循环pass
     	{ 
        	$pwd=trim(fgets($file_name));//读取pass
        	echo "pwd=".$pwd."\n";echo "salt=".$salt."\n";
        	if($pwd == md5(md5($password).$salt))
        	{
        		echo "就是你了:".$pwd."\n---------------------------------\n";exit;
        	}
        	else
        	{
        		echo $pwd."|"."不是密码$password|".$ii++."\n";
        	}
     	}
   		fclose($file_name);
    }
    fclose($file1_name);
    echo "指定密码猜测失败！\n";
}

/*
*测试模块2
*以用户作为密码测试
*/
function test_2()
{
	echo "开始测试密码\n--------------------------------------\n";
	$file1_name = fopen("salt.txt","r");//打开salt
  	while(!feof($file1_name))//循环salt
  	{
  	  	$salt=trim(fgets($file1_name));//读取salt
     	$file_name = fopen("pass.txt","r");//打开pass
     	while(!feof($file_name))//循环pass
     	{ 
     		$pwd=trim(fgets($file_name));//读取pass
        	$file_name2 = fopen("user.txt","r");//打开user
     	 	while(!feof($file_name2))//循环user
     	 	{
     	  		$user=trim(fgets($file_name2));//读取user
     	  		echo "user=".$user."\n";echo "pwd=".$pwd."\n";echo "salt=".$salt."\n";
         		if($pwd== md5(md5($user).$salt))
         		{
         			echo "就是你了:user=".$user."\n";echo "pwd=".$pwd."\n";echo "salt=".$salt."\n";
        			echo "\n-----------------------------\n";exit;
         		}
         		else
         		{
         		echo $pwd."  "."不是密码2！"."\n";
         		}
         	}
         	fclose($file_name2);
        }
        fclose($file_name);
    }
    fclose($file1_name);
    echo "以用户作为密码测试失败！\n";
}
/*
*测试模块3
*以用户和6位以内的随即数作为密码测试
*/
function test_3()
{
	echo "开始测试密码\n--------------------------------------\n";
	randmunber();
	$file1_name = fopen("salt.txt","r");//打开salt
  	while(!feof($file1_name))//循环salt
  	{
  	  	$salt=trim(fgets($file1_name));//读取salt
     	$file_name = fopen("pass.txt","r");//打开pass
     	while(!feof($file_name))//循环pass
     	{ 
     		$pwd=trim(fgets($file_name));//读取pass
        	$file_name2 = fopen("user.txt","r");//打开user
     	 	while(!feof($file_name2))//循环user
     	 	{
     	  		$user=trim(fgets($file_name2));//读取user
    			$randmun=fopen("rand.txt","r");//打开随机数
    			while(!feof($randmun))//循环随机数
         		{
         	 		$randm=trim(fgets($randmun));//读取随机数
         	 		echo "user=".$user."\n";echo "pwd=".$pwd."\n";echo "salt=".$salt."\n";echo "rand=".$randm."\n";
         			if($pwd== md5(md5($user.$randm).$salt))
         			{
         	 			echo "就是你了user+rand=".$user.$randm."\n"."user=".$user."\n";
         	 			echo "pwd=".$pwd."\n";
         	 			echo "salt=".$salt."\n";
         	 			echo "rand=".$randm."\n";
        				echo "\n-----------------------------\n";exit;
         			}
         			else
         			{
         				echo $pwd."|"."不是密码3！\n";}
         		}	
				fclose($randmun);
      		}
      		fclose($file_name2);
      	}
      	fclose($file_name);
    }
     fclose($file1_name);
     echo "以用户+6位随机数作为密码测试失败！\n";
}
/*
*生产随机数
*/
function randmunber()
{
	if(!file_exists("rand.txt"))
	{
		$randmun=fopen("rand.txt","w");
		for($i=0;$i<999999;$i++)
		{
			fwrite($randmun,$i."\n");
		}
		fclose($randmun);
	}
}
?>