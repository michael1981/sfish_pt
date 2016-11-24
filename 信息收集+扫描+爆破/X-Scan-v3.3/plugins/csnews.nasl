#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (4/15/009)


include("compat.inc");

if(description)
{
 script_id(11726);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2002-0923");
 script_bugtraq_id(4994);
 script_xref(name:"OSVDB", value:"8134");
 
 script_name(english:"CGIScript.net csNews.cgi Advanced Settings Multiple Parameter Arbitrary File Retrieval");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected by
an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The CSNews.cgi exists on this webserver. Some versions of this file 
are vulnerable to remote exploit. An attacker can submit a specially
crafted web form, which can display the 'setup.cgi' file that contains
the superuser name and password." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-06/0091.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for the csnews.cgi file");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 John Lampe");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
banner = get_http_banner(port:port);
if ( ! banner || "Server: Microsoft/IIS" >!< banner ) exit(0);

flag = 0;
directory = "";

foreach dir (cgi_dirs()) {
   if(is_cgi_installed_ka(item:string(dir, "/csNews.cgi"), port:port)) {
  	flag = 1;
  	directory = dir;
  	break;
   } 
}
 
if (flag) security_hole(port);
