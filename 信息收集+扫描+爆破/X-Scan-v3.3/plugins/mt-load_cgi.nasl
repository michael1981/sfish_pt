#
# This script was written by Rich Walchuck (rich.walchuck at gmail.com)
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin description (3/25/2009)


include("compat.inc");

if(description)
{
 script_id(16169);
 script_version ("$Revision: 1.4 $");
 script_name(english:"Movable Type mt-load.cgi Privilege Escalation");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected
by a privilege escalation vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote web server is hosting Movable Type with 'mt-load.cgi' 
installed.

Failure to remove mt-load.cgi could enable someone else to create
a weblog in your Movable Type installation, and possibly gain access 
to your data." );
 script_set_attribute(attribute:"solution", value:
"Remove the mt-load.cgi script after installation." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Checks for the existence of /mt/mt-load.cgi");
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Rich Walchuck");
 script_family(english:"CGI abuses");
 script_require_ports("Services/www",80);
 script_dependencies("http_version.nasl");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:80);

if(is_cgi_installed_ka(item:"/mt/mt-load.cgi",port:port))
       security_warning(port);

