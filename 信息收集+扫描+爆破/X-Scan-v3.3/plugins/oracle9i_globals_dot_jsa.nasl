#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref, description touch-up (6/9/09)


include("compat.inc");

if(description)
{
 script_id(10850);
 script_version("$Revision: 1.16 $");
 script_cve_id("CVE-2002-0562");
 script_bugtraq_id(4034);
 script_xref(name:"OSVDB", value:"707");
 script_xref(name:"IAVA", value:"2002-t-0006");

 script_name(english:"Oracle 9iAS globals.jsa Database Credential Remote Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"Sensitive data may be disclosed on the remote host." );
 script_set_attribute(attribute:"description", value:
"In the default configuration of Oracle 9iAS, it is possible to make 
requests for the globals.jsa file for a given web application. 
These files should not be returned by the server as they often 
contain sensitive information such as database credentials." );
 script_set_attribute(attribute:"see_also", value:"http://www.nextgenss.com/advisories/orajsa.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/" );
 script_set_attribute(attribute:"solution", value:
"Edit httpd.conf to disallow access to *.jsa." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Tests for Oracle9iAS globals.jsa access");
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
# Make a request for one of the demo files .jsa files. This can be 
# improved to use the output of webmirror.nasl, allowing the plugin to
# test for this problem in configurations where the demo files have
# been removed.

 req = http_get(item:"/demo/ojspext/events/globals.jsa",
 		port:port); 
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("event:application_OnStart" >< r)	
 	security_warning(port);

 }
}
