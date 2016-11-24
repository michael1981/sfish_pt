#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11810);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2003-0614");
 script_bugtraq_id(8288);
 script_xref(name:"OSVDB", value:"2322");

 script_name(english:"Gallery search.php searchstring Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a cross-
site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Gallery web-based photo album. 

There is a flaw in the version of Gallery installed on the remote host
that makes it vulnerable to a cross-site scripting attack due to a
failure to properly sanitize input to the 'searchstring' parameter of
the 'search.php' script.  A remote attacker may use this to steal the
cookies from the legitimate users of this system." );
 script_set_attribute(attribute:"see_also", value:"http://gallery.menalto.com/node/82" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Gallery 1.3.4p1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks for the presence of search.php");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("find_service1.nasl", "http_version.nasl", "cross_site_scripting.nasl");
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
if(!can_host_php(port:port)) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

function check(url)
{
  local_var r;
  global_var port;

  r = http_send_recv3(method: 'GET', item:string(url, "/search.php?searchstring=<script>foo</script>"),	port:port);
  if (isnull(r)) exit(0);
  if(r[0] =~ "^HTTP/1\.[01] +200 " && "<script>foo</script>" >< r && "<!-- search.header begin -->" >< r[2])
 	{
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
	}
 
}

foreach dir (cgi_dirs())
{
 check(url:dir);
}
