#
# This script was written by Rich Walchuck (rich.walchuck at gmail.com)
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Reformatted description and added dependency (7/7/2009)
# - Revised plugin title (3/25/2009)


include("compat.inc");

if(description)
{
 script_id(16170);
 script_version ("$Revision: 1.5 $");
 script_name(english:"Movable Type mt.cfg Information Disclosure");
 script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is disclosing sensitive
information." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Movable Type.  The file 'mt.cfg' is
publicly accessible, and contains information that should not be exposed." );
 script_set_attribute(attribute:"solution", value:
"Configure your web server not to serve .cfg files." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Checks for the presence of mt.cfg");
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Rich Walchuck");
 script_family(english:"CGI abuses");
 script_require_ports("Services/www",80);
 script_dependencies("http_version.nasl", "movabletype_detect.nasl");

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:80);

install = get_kb_item("www/" + port + "/movabletype");
if (isnull(install))
  exit(1, "Unable to find an install of Movable Type on port " + port);

match = eregmatch(string:install, pattern:'^.+ under (/.*)$');
if (isnull(match))
  exit(1, "Error retrieving dir of Movable Type installation from the KB.");

mt_dir = match[1];
url = string(mt_dir, '/mt.cfg');
if(is_cgi_installed_ka(item:url, port:port))
   security_warning(port);

