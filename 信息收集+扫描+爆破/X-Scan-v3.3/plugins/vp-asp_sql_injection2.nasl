# 
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(19229);
 script_version ("$Revision: 1.8 $");
 script_bugtraq_id(14295, 14305, 14306);
 script_xref(name:"OSVDB", value:"17998");
 script_xref(name:"OSVDB", value:"17999");
 script_xref(name:"OSVDB", value:"18000");

 script_name(english:"VP-ASP Multiple Script SQL Injection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has a ASP script that is affected by a SQL
injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is using the VP-ASP, a shopping cart program written
in ASP.  The remote version of this software contains three SQL
injection vulnerabilities in the files shopaddtocart.asp,
shopaddtocartnodb.asp and shopproductselect.asp.  An attacker may
exploit these flaws to execute arbitrary SQL statements against the
remote database." );
 script_set_attribute(attribute:"solution", value:
"See http://www.vpasp.com/virtprog/info/faq_securityfixes.htm" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

 script_summary(english:"Performs a SQL injection against the remote shopping cart");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

foreach dir ( cgi_dirs() )
{
  res = http_send_recv3(method:"GET", item:dir + "/shopaddtocart.asp?productid='42", port:port);
  if(isnull(res))exit(1, "Null response to shopaddtocart.asp request.");
  if("'80040e14'" >< res[2] && "[Microsoft][ODBC SQL Server Driver][SQL Server]" >< res[2] && "'42'" >< res[2] )
 {
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  exit(0);
 }
}
