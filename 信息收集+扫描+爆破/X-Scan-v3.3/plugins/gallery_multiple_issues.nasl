#
# (C) Tenable Network Security, Inc.
#
#


include("compat.inc");

if(description)
{
 script_id(16185);
 script_cve_id("CVE-2005-0219", "CVE-2005-0220", "CVE-2005-0221", "CVE-2005-0222");
 script_bugtraq_id(12292, 12286);
 script_xref(name:"OSVDB", value:"13029");
 script_xref(name:"OSVDB", value:"13034");
 script_xref(name:"OSVDB", value:"13033");
 script_xref(name:"OSVDB", value:"13030");
 script_xref(name:"OSVDB", value:"13031");
 script_xref(name:"OSVDB", value:"13032");
 script_xref(name:"OSVDB", value:"13922");

 script_version ("$Revision: 1.10 $");

 script_name(english:"Gallery < 1.4.4-pl5 Multiple Remote Vulnerabilities (XSS, Path Disc)");
 script_summary(english:"Checks for the presence of login.php");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected
by multiple remote vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Gallery web-based photo album.

The installed version of Gallery is fails to properly sanitize user
supplied input to the 'username' parameter of the 'login.php' script.
An attacker could exploit this flaw to launch cross-site scripting
attacks.

Note that the installed version is reportedly affected by multiple
other vulnerabilities, though Nessus has not tested for these." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-01/0380.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Gallery 1.4.4-pl6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );


script_end_attributes();

 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("cross_site_scripting.nasl");
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

if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
exploit = '"<script>foo</script';
function check(url)
{
local_var req;

req = http_send_recv3(method:"GET", item:string(url, '?username=', exploit), port:port);
if (isnull(req)) exit(0);
if('<input type=text name="username" value=""<script>foo</script>"' >< req[2] )
 	{
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
	}
}

foreach dir (cgi_dirs())
 check(url:dir);
