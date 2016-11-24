#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: GOBBLES advisory on December 29th, 2001.
#
#  This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - Revised plugin title, changed family (4/6/2009)


include("compat.inc");

if(description)
{
 script_id(15621);
 script_version("$Revision: 1.9 $");

 script_cve_id("CVE-2001-1432");
 script_bugtraq_id(3772);
 script_xref(name:"OSVDB", value:"16980");

 script_name(english:"Cherokee Web Server URI Traversal Arbitrary File Access");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Cherokee - a fast and tiny web server.

The remote version of this software is vulnerable to directory
traversal flaw when appending a '../' sequence to the web request.

Additionally, this version fails to drop root privileges after it 
binds to listen port.

Remote attacker can then submit specially crafted web request to 
browse any file on the server with root privileges." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/vulnwatch/2001-q4/0085.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Cherokee 0.2.8 or newer as this reportedly fixes the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks for version of Cherokee");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Cherokee/0\.([01]\.|2\.[0-7])[^0-9]", string:serv))
 {
   security_warning(port);
 }
