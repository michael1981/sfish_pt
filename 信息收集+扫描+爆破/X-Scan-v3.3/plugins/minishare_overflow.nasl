#
# written by Gareth Phillips - SensePost PTY ltd (www.sensepost.com)
#
# Changes by Tenable:
# - detect title to prevent false positives
# - fix version detection
# - added CVE and OSVDB xrefs.
# - revised plugin title, changed family, update output formatting (8/18/09)



include("compat.inc");

if(description)
{
 script_id(18424);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2004-2271");
 script_bugtraq_id (11620);
 script_xref(name:"OSVDB", value:"11530");

 script_name(english:"MiniShare Webserver HTTP GET Request Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote buffer overflow 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"MiniShare 1.4.1 and prior versions are affected by a buffer overflow 
flaw. A remote attacker could execute arbitrary commands by sending a
specially crafted file name in a the GET request.

Version 1.3.4 and below do not seem to be vulnerable." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-11/0208.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MiniShare 1.4.2 or higher." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"MiniShare webserver buffer overflows");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 SensePost");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# Code Starts Here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
res = http_get_cache(item:"/", port:port);
if( res == NULL ) exit(0);
if ("<title>MiniShare</title>" >!< res)
  exit (0);

if (egrep (string:res, pattern:'<p class="versioninfo"><a href="http://minishare\\.sourceforge\\.net/">MiniShare 1\\.(3\\.([4-9][^0-9]|[0-9][0-9])|4\\.[0-1][^0-9])'))
  security_hole (port);
}
