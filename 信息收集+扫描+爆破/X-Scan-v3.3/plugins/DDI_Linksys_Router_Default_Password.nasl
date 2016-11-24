#
# This script is Copyright (C) Digital Defense Inc.
# Author: Forrest Rae <forrest.rae@digitaldefense.net>
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
	script_id(10999);
	script_version("$Revision: 1.11 $");
	script_cve_id("CVE-1999-0508");

	script_name(english:"Linksys Router Default Password");

	script_set_attribute(attribute:"synopsis", value:
"The remote system can be accessed with a default administrator
account." );
	script_set_attribute(attribute:"description", value:
"The remote Linksys router accepts the default password 'admin' for
the web administration console.  This console provides read/write
access to the router's configuration.  An attacker could take
advantage of this to reconfigure the router and possibly re-route
traffic." );
	script_set_attribute(attribute:"solution", value:
"Change the password for this account." );
	script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_set_attribute(attribute:"plugin_publication_date", value:
"2002/06/05");
	script_end_attributes();

	script_summary(english: "Linksys Router Default Password (admin)");
	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2002-2009 Digital Defense Inc.");
	script_family(english:"CISCO");
	script_dependencie("http_version.nasl");
	script_require_ports(80,8080);
        script_require_keys("Services/www");
	exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = 80;
if (!get_port_state(port))port = 8080;

if(get_port_state(port))
{
	soc = open_sock_tcp(port);
	if (soc)
	{
	
		# HTTP auth = ":admin"
		# req = string("GET / HTTP/1.0\r\nAuthorization: Basic OmFkbWlu\r\n\r\n");
		
		# HTTP auth = "admin:admin"
		req = string("GET / HTTP/1.0\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n");
		
		# Both work, second is used to be RFC compliant.
		
		send(socket:soc, data:req);
		buf = http_recv(socket:soc);
		close(soc);
		if (!isnull(buf) && ("Status.htm" >< buf) && ("DHCP.htm" >< buf) && ("Log.htm" >< buf) && ("Security.htm" >< buf))
		{
			security_hole(port:port);
		}
	}
}
