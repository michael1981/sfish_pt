#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10122);
 script_version ("$Revision: 1.34 $");
 script_cve_id("CVE-1999-0951");
 script_bugtraq_id(739);
 script_xref(name:"OSVDB", value:"3380");

 script_name(english:"OmniHTTPd imagemap.exe CGI Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a CGI that is affected by a remote 
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The 'imagemap.exe' cgi is installed. This CGI is vulnerable to a 
buffer overflow that will allow a remote user to execute arbitrary 
commands with the privileges of your httpd server (either nobody or
root)." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1999-q3/1367.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OmniHTTPD 2.10 or later, as this reportedly fixes the 
issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Overflows /cgi-bin/imagemap.exe");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
sig = get_http_banner(port:port);
if ( sig && "Server: Microsoft/IIS" >!< sig ) exit(0);

flag = 0;

foreach dir (cgi_dirs())
{
 if(is_cgi_installed_ka(item:string(dir, "/imagemap.exe"), port:port))
 { 
  flag = 1;
  directory = dir;
  break;
 }
}

if(!flag)exit(0);

s = string(directory, "/imagemap.exe?", crap(5000));
soc = http_open_socket(port);
if(soc)
 {
 s = http_get(item:s, port:port);
 send(socket:soc, data:s);
 r = http_recv(socket:soc);
 if(!r)security_hole(port);
 http_close_socket(soc);
 }


