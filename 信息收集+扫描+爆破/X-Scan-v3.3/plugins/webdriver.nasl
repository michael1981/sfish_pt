#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10592);
 script_version ("$Revision: 1.19 $");
 script_bugtraq_id(2166);
 script_xref(name:"OSVDB", value:"489");

 script_name(english:"Informix webdriver CGI Unauthenticated Database Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that may fail to restrict
access to an installed database." );
 script_set_attribute(attribute:"description", value:
"The remote host may be running Informix Webdriver, a web-to-database
interface.  If not configured properly, this CGI script may give an
unauthenticated attacker the ability to modify and even delete
databases on the remote host. 

*** Nessus relied solely on the presence of this CGI; it did not
*** try to determine if the installed version is vulnerable to 
*** that problem." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-01/0002.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-01/0043.html" );
 script_set_attribute(attribute:"solution", value:
"Consult the product documentation to properly configure the script." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks for the presence of Webdriver");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

res = is_cgi_installed3(port:port, item:"webdriver");
if(res)security_warning(port);
