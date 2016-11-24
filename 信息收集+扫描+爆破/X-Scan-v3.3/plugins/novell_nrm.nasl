#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(20747);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2005-3655");
 script_bugtraq_id(16226);
 script_xref(name:"OSVDB", value:"22455");

 script_name(english:"Novell Open Enterprise Server Remote Manager (novell-nrm) POST Request Content-Length Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote web server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Novell Remote Manager HTTP service
for SuSE Enterprise or Open Enterprise Server.

The remote version of this software is vulnerable to a heap overflow
attack that may be exploited by sending a negative value for the
'Content-Length' field. 

Since the 'httpstkd' service runs with the root privileges, an
attacker can leverage this issue to gain full control of the remote
host." );
 script_set_attribute(attribute:"solution", value:
"Novell has released a patch for the novell-nrm service :
http://www.novell.com/linux/security/advisories/2006_02_novellnrm.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks for Novel Remort Manager HTTP Heap Overflow");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8008, 8009);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8008);
if (!get_port_state (port))
  exit (0);

banner = get_http_banner (port:port);

if ("NetWare HTTP Stack" >!< banner)
  exit (0);

req = string ("POST / HTTP/1.0\r\n",
              "Content-Length: -2147483648\r\n\r\n");

rep = http_keepalive_send_recv(port:port, data:req);


# patched version replies with "HTTP/1.1 400 Bad request"

if (rep && ("HTTP/1.1 500 Malfunction" >< rep))
  security_hole(port);

