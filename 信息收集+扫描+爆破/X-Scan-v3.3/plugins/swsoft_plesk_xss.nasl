#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14369);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2004-2702");
 script_bugtraq_id(11024);
 script_xref(name:"OSVDB", value:"9149");
 script_xref(name:"Secunia", value:"12368");
 
 script_name(english:"Plesk Reloaded login_up.php3 login_name Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Plesk Reloaded (from SWsoft), a web based
system administration tool. 

The remote version of this software is vulnerable to a cross-site
scripting attack because of its failure to sanitize user input to the
'login_name' parameter of the 'login_up.php3' script.  This issue can
be used to take advantage of the trust between a client and server
allowing the malicious user to execute malicious JavaScript on the
client's machine." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-08/1022.html" );
 script_set_attribute(attribute:"solution", value:
"Reportedly the vendor has issued patches, which are available via its
web site or the software's autoupdate feature." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
 summary["english"] = "Checks for the presence of an XSS bug in Plesk Reloaded";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("cross_site_scripting.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);
if (  get_kb_item(string("www/", port, "/generic_xss")) ) exit(0);

function check(loc)
{
 local_var r;
 global_var port;

 r = http_send_recv3(method: "GET", item:string(loc, "/login_up.php3?login_name=<script>foo</script>"), port:port);
 if (isnull(r)) exit(0);
 if(r[0] =~ "^HTTP/1\.[01] +200 " && '<script>foo</script>' >< r[2])
 {
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

