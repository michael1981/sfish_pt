#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# www.westpoint.ltd.uk
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Ian Koenig <ian@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10670);
 script_version ("$Revision: 1.15 $");
 script_xref(name:"OSVDB", value:"555");

 script_name(english:"PHP3 Error Message Physical Path Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server may be vulnerable to information disclosure." );
 script_set_attribute(attribute:"description", value:
"PHP3 will reveal the physical path of the webroot when asked for a 
nonexistent PHP3 file if it is incorrectly configured. Although printing
errors to the output is useful for debugging applications, this feature
should not be enabled on production servers." );
 script_set_attribute(attribute:"solution", value:
"In the PHP configuration file change display_errors to 'Off':
   display_errors  =   Off" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-06/0143.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 summary["english"] = "Tests for PHP3 Physical Path Disclosure Vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001-2009 Matt Moore");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Actual check starts here...
# Check makes a request for nonexistent php3 file...

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 
 if ( ! can_host_php(port:port) ) exit(0);
 req = http_get(item:"/nosuchfile-10303-10310.php3", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("Unable to open" >< r)	
 	security_warning(port);

 }
}
