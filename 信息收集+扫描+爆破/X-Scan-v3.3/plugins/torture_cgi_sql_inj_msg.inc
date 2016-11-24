# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# torture_cgi_sql_inj_msg.inc
# $Revision: 1.1 $
#

global_var	global_patterns;

i = 0;
global_patterns[i++] = "ST:Unable to connect to PostgreSQL server:";
global_patterns[i++] = "ST:Column count doesn't match value count at row";
global_patterns[i++] = "ST:error " + single_quote + "80040e14";
global_patterns[i++] = "ST:Incorrect column name";
global_patterns[i++] = "ST:Incorrect column specifier for column";
global_patterns[i++] = "ST:Invalid parameter type";
global_patterns[i++] = "ST:Microsoft OLE DB Provider for";
global_patterns[i++] = "ST:ODBC Microsoft Access Driver";
global_patterns[i++] = "ST:ODBC SQL Server Driver";
global_patterns[i++] = "ST:supplied argument is not a valid MySQL result";
global_patterns[i++] = "ST:mysql_query()";
global_patterns[i++] = "ST:Unknown table";
global_patterns[i++] = "ST:You have an error in your SQL syntax";
global_patterns[i++] = "ST:Error Occurred While Processing Request";
global_patterns[i++] = "ST:[IBM][CLI Driver][DB2/6000]";
global_patterns[i++] = "ST:not a valid MySQL result resource";
global_patterns[i++] = "ST:unexpected end of SQL command";
global_patterns[i++] = "ST:mySQL error with query";
global_patterns[i++] = "ST:Can't connect to local";
global_patterns[i++] = "ST:ADODB.Recordset";
global_patterns[i++] = "ST:Unclosed quotation mark before the character string";
global_patterns[i++] = "ST:Incorrect syntax near";
global_patterns[i++] = "ST:PostgreSQL query failed:";
global_patterns[i++] = "ST:not a valid PostgreSQL result";
global_patterns[i++] = "ST:An illegal character has been found in the statement";
global_patterns[i++] = "ST:SQLSTATE:";
global_patterns[i++] = "ST:SQL command not properly ended";
global_patterns[i++] = "ST:mysql_connect(): Access denied";
global_patterns[i++] = "ST:[SQL Server";
global_patterns[i++] = "ST:[ODBC SQL";
global_patterns[i++] = "ST:on MySQL result index";
# From torturecgis.nasl
global_patterns[i++] = "ST:PL/SQL";
global_patterns[i++] = "ST:MySQL query";
# MA 2008-05-06: I saw that on Tomcat.
global_patterns[i++] = "ST:Unexpected end of command in statement";
global_patterns[i++] = "ST:System.Data.OleDb.OleDbException:";

# -933ORA-00933: SQL command not properly ended
global_patterns[i++] = "RE:ORA-[0-9]{5}[^0-9]";
global_patterns[i++] = "RE:ODBC Error Code.*=.*[a-zA-Z]+[0-9]+";
# MA 2009-05-19
global_patterns[i++] = "RE:[sS]yntax error (.* )?in query expression";

