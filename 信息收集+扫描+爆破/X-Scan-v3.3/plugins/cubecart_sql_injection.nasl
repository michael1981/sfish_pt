#
# (C) Tenable Network Security
#

include("compat.inc");

if(description)
{
 script_id(15442);
 script_version("$Revision: 1.10 $");

 script_cve_id("CVE-2004-1580");
 script_bugtraq_id(11337);
 script_xref(name:"OSVDB", value:"10584");

 script_name(english:"CubeCart index.php cat_id Parameter SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"There is a SQL injection issue in the remote version of CubeCart that
may allow an attacker to execute arbitrary SQL statements on the
remote host and to potentially overwrite arbitrary files on the remote
system, by sending a malformed value to the 'cat_id' argument of the
file 'index.php'." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/lists/bugtraq/2004/Oct/0051.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.cubecart.com/site/forums/index.php?showtopic=4065" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CubeCart 2.0.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "SQL Injection in CubeCart";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_dependencies("cubecart_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);

 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if ( ! can_host_php(port:port) ) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/cubecart"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];

 r = http_send_recv3(method:"GET", port:port, item: loc + "/index.php?cat_id=42'");
 if (isnull(r)) exit(0);
 res = strcat(r[0], r[1], '\r\n', r[2]);

 if ("mysql_fetch_array()" >< res)
 {
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
 }
}
