#
# Copyright 2001 by H D Moore <hdmoore@digitaldefense.net>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, changed family (1/22/09)
# - Revised plugin title, output formatting (9/3/09)

include("compat.inc");

if(description)
{
 script_id(10826);
 script_version("$Revision: 1.14 $");

 # script_cve_id("CVE-MAP-NOMATCH");
 # NOTE: reviewed, and no CVE id currently assigned (jfs, december 2003)

 script_name(english:"Novell NetWare Management Portal Unrestricted Access");
 script_summary(english:"Unprotected NetWare Management Portal");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server discloses sensitive information.");
script_set_attribute(attribute:"description", value:
"The NetWare Management Portal software is running on this machine.  It
allows anyone to view the current server configuration and locate
other Portal servers on the network.  It is possible to browse the
server's filesystem by requesting the volume in the URL.  However, a
valid user account is needed to do so.");
 script_set_attribute(attribute:"solution", value: 
"Disable this service if it is not in use or block connections to
it.");
 script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
 script_set_attribute(attribute:"plugin_publication_date", value:
"2001/12/12");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Digital Defense Inc.");
 script_family(english:"Netware");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8008);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


# ssl version sometimes on port 8009
port = get_http_port(default:8008);

banner = get_http_banner(port:port);
if(! banner ) exit(0);

if (egrep(pattern:"^Server: NetWare Server", string:banner) ) security_warning(port);
