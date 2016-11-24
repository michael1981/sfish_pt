#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14368);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-2004-1746");
 script_bugtraq_id(11038);
 script_xref(name:"OSVDB", value:"9168");
 
 script_name(english:"PHP Code Snippet Library index.php Multiple Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script affected by a cross-site
scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHP Code Snippet Library (PHP-CSL), a
library written in PHP. 

The remote version of this software is fails to sanitize input to the
'cat_select' parameter of the 'index.php' script.  This can be used to
take advantage of the trust between a client and server allowing the
malicious user to execute malicious JavaScript on the client's
machine." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-08/0325.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP-CSL version 0.9.1 or later as that is rumored to
address the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
 script_summary(english:"Checks for the presence of an XSS bug in PHP-CSL");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
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

if(!can_host_php(port:port))exit(0);
if (  get_kb_item(string("www/", port, "/generic_xss")) ) exit(0);

function check(loc)
{
 local_var r, w;
 global_var port;

 w = http_send_recv3(method:"GET", item:string(loc, "/index.php?cat_select=<script>foo</script>"), port:port);
 if (isnull(w)) exit(0);
 r = w[2];
 
 if('<script>foo</script>' >< r && "PHP-CSL" >< r)
 {
 	security_warning(port:port, extra:'\nThe following URL is vulnerable :\n' + loc + "/index.php?cat_select=<script>foo</script>");
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}
