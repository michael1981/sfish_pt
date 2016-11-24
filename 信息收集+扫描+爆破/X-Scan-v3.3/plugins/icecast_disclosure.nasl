#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security 
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(11044);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2002-1982");
 script_bugtraq_id(5189);
 script_xref(name:"OSVDB", value:"847");
 
 script_name(english:"Icecast list_directory Function Traversal File/Directory Enumeration");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote server does not return the same error codes when it is
requested a nonexistent directory and an existing one.  An attacker
may use this flaw to deduct the presence of several key directory on
the remote server, and therefore gain further knowledge about it." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/vuln-dev/2002-q3/0095.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Icecast 2.0 as this reportedly fixes the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"Determines if the error code is the same when requesting non-existing and existing dirs");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8000);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:8000);
if(!port) exit(0);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
if ( "icecast/" >!< tolower(banner) ) exit(0);

req1 = http_send_recv3(method:"GET", item:"/test/../../../../../../../../../inexistant_i_hope/", port: port);
req2 = http_send_recv3(method:"GET", item:"/test/../../../../../../../../../etc/", port: port);

if (!(r2 == r1)) security_warning(port);
