#
# (C) Tenable Network Security, Inc.
#
#


include("compat.inc");

if(description)
{
 script_id(15624);
 script_cve_id("CVE-2004-1106");
 script_bugtraq_id(11602);
 script_xref(name:"OSVDB", value:"11340");
 script_version ("$Revision: 1.11 $");

 script_name(english:"Gallery Unspecified HTML Injection");
 script_summary(english:"Checks for the version of Gallery");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
a HTML injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Gallery web-based photo album.

There is a flaw in the remote version of this software which may
allow an attacker to inject arbitrary HTML tags in the remote web
server." );
 script_set_attribute(attribute:"see_also", value:"http://gallery.menalto.com/node/142" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/7838" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/7461" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Gallery 1.4.4-pl3 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http.inc");
include("misc_func.inc");
include("global_settings.inc");

port = get_http_port(default:80, embedded: 0);
if(!can_host_php(port:port)) exit(0);

function check(url)
{
local_var r;

r = http_send_recv3(method:"GET", item:string(url, "/index.php"),port:port);

if (isnull(r)) exit(0);
if ( egrep(pattern:".*Powered by.*Gallery.*v(0\.|1\.([0-3]\.|4\.([0-3][^0-9]|4 |4-pl[0-2]([^0-9]|$))))", string:r) )
	{
	security_warning(port);
	exit(0);
	}
}

check(url:"");
foreach dir (cgi_dirs())
{
 check(url:dir);
}
