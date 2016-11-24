#
# This script was written by Thomas Reinke <reinke@e-softinc.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, OSVDB ref, output formatting, family change (9/5/09)


include("compat.inc");

if(description)
{
 script_id(10533);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2000-0922");
 script_bugtraq_id(1776);
 script_xref(name:"OSVDB", value:"432");
 
 script_name(english:"Bytes Interactive Web Shopper shopper.cgi Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host contains is running Byte's Interactive Web Shopper, a
shopping cart application. The installed version allows for retrieval
of arbitrary files from the webserver." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-10/0120.html" );
 script_set_attribute(attribute:"solution", value:
"Uncomment the '#$debug=1' variable in the scripts so that it will
check for and disallow viewing of aribtrary files." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Web Shopper remote file retrieval");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Thomas Reinke");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 buf = string(dir, "/shopper.cgi?newpage=../../../../../../etc/passwd");
 buf = http_get(item:buf, port:port);
 rep = http_keepalive_send_recv(port:port, data:buf);
 if(rep == NULL)exit(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:rep))
  	security_warning(port);
}
