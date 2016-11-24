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
# - Revised plugin title, added extra OSVDB ref (6/9/09)


include("compat.inc");

if(description)
{
 script_id(10848);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2002-0563");
 script_bugtraq_id(4293);
 script_xref(name:"OSVDB", value:"705");
 script_xref(name:"OSVDB", value:"44590");

 script_name(english:"Oracle 9iAS DMS / JPM Pages Anonymous Access");
 
 script_set_attribute(attribute:"synopsis", value:
"Sensitive resources can be accessed." );
 script_set_attribute(attribute:"description", value:
"In a default installation of Oracle 9iAS, it is possible to access the 
Dynamic Monitoring Services pages anonymously. Access to these pages 
should be restricted." );
 script_set_attribute(attribute:"solution", value:
"Edit httpd.conf to restrict access to /dms0." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"Tests for presence of Oracle9iAS Dynamic Monitoring Services");
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
 req = http_get(item:"/dms0", port:port);	      
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("DMSDUMP version" >< r)	
 	security_warning(port);

 }
}
