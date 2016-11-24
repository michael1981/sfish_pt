#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
	script_id(11737);
	script_version("$Revision: 1.7 $");

	script_name(english:"NETGEAR Router Default Password (password) for 'admin' Account");
	script_summary(english:"NETGEAR Router Default Password");

	script_set_attribute(
    attribute:'synopsis',
    value:'The remote service has a well known default password.'
  );

  script_set_attribute(
    attribute:'description',
    value:"This NETGEAR Router/Access Point has the default password
set for the web administration console. ('admin'/'password').

This console provides read/write access to the router's configuration.
An attacker could take advantage of this to reconfigure the router and
possibly re-route traffic."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Configure a strong password for the web administration console."
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
	script_family(english:"Misc.");
	script_dependencie("find_service1.nasl");
	script_require_ports(80);
	exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);
if ( port != 80 ) exit(0);


if(get_port_state(port))
{
	soc = open_sock_tcp(port);
	if (soc)
	{

		req = string("GET /top.html HTTP/1.1\r\nUser-Agent: Mozilla/5.0\r\nReferer: http://192.168.0.1/\r\nAuthorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n\r\n");
		send(socket:soc, data:req);
		buf = http_recv(socket:soc);
		close(soc);
		if("<title>NETGEAR</title>" >< buf && "img/hm_icon.gif" >< buf && "Server: Embedded HTTPD v1.00" >< buf)
		{
			security_hole(port:port);
		}
	}
}
