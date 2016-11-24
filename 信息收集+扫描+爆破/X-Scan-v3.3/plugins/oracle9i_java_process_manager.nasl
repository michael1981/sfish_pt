#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (6/10/09)


include("compat.inc");

if(description)
{
 script_id(10851);
 script_version("$Revision: 1.16 $");

 script_cve_id("CVE-2002-0563");
 script_bugtraq_id(4293);
 script_xref(name:"OSVDB", value:"13152");

 script_name(english:"Oracle 9iAS Java Process Manager /oprocmgr-status Anonymous Process Manipulation");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the list of Java processes running on the
remote host anonymously, as well as to start and stop them." );
 script_set_attribute(attribute:"description", value:
"The remote host is an Oracle 9iAS server. By default, accessing
the location /oprocmgr-status via HTTP lets an attacker obtain
the list of processes running on the remote host, and even to
to start or stop them." );
 script_set_attribute(attribute:"solution", value:
"Restrict access to /oprocmgr-status in httpd.conf" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_summary(english:"Tests for Oracle9iAS Java Process Manager");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Matt Moore");
 script_family(english:"Databases");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 exit(0);
}

# Check starts here

include("http_func.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{ 
# Make a request for /oprocmgr-status

 req = http_get(item:"/oprocmgr-status", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("Module Name" >< r)	
 	security_warning(port);

 }
}
