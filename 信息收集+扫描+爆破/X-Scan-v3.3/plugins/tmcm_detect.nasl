#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - Revised plugin title, output formatting, family change (9/3/09)

include("compat.inc");

if(description)
{
 script_id(18178);
 script_version("$Revision: 1.5 $");
 
 script_name(english:"Trend Micro TMCM Console Management Detection");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web management console is leaking information."
 );
 script_set_attribute(
   attribute:"description",
   value:
"The remote host appears to run Trend Micro Control Manager.  It is
accepting connections to the web console management interface, which
may reveal sensitive information.  A remote attacker could use this
information to mount further attacks."
 );
 script_set_attribute(
   attribute:"solution",
   value:"Filter incoming traffic to this port."
 );
 script_set_attribute(
   attribute:"cvss_vector",
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_summary(english:"Checks for Trend Micro TMCM console management");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 script_family(english:"CGI abuses");
 script_dependencie("httpver.nasl");
 script_require_ports(80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port || port != 80 ) exit(0);

if(get_port_state(port))
{
 req = http_get(item:"/ControlManager/default.htm", port:port);
 rep = http_keepalive_send_recv(port:port, data:req);
 if( rep == NULL ) exit(0);

#<title>
#Trend Micro Control Manager 3.0
#</title>

 if (egrep(pattern:"Trend Micro Control Manager.+</title>", string:rep, icase:1))
 {
	set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
	security_warning(port);
 }
}

