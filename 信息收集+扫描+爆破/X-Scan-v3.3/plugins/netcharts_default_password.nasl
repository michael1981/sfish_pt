#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
	script_id(11600);
	script_version("$Revision: 1.5 $");
	script_name(english:"NetCharts Server Default Password");
	script_summary(english:"NetCharts Server Default Password");

	script_set_attribute(
    attribute:'synopsis',
    value:'The remote service has a well known default password.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote host is running the NetCharts server on this port,
with the default login and password of 'Admin/Admin'.

An attacker may use this misconfiguration to administrate
the remote server."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Change the password of the 'Admin' account to stronger one."
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
	script_family(english:"CGI abuses");
	script_dependencie("http_version.nasl");
	script_require_ports("Services/www", 8001);
	exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:8001);
if ( ! port ) exit(0);

# HTTP auth = "Admin:Admin"
req = string("GET /Admin/index.jsp HTTP/1.1\r\nHost: ", get_host_name(), "\r\n", "Authorization: Basic QWRtaW46QWRtaW4=\r\n\r\n");
res = http_keepalive_send_recv(port:port, data:req);
if(res != NULL && egrep(pattern:"HTTP.* 200 .*", string:res) && "NetCharts Server" >< res) security_hole(port);
