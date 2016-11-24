#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if (description)
{
  script_id(18048);
  script_cve_id("CVE-2005-1135");
  script_bugtraq_id(13170);
  script_xref(name:"OSVDB", value:"15846");
  script_version ("$Revision: 1.10 $");

  script_name(english:"sphpblog search.php q Parameter XSS");
  script_summary(english:"Determine if sphpblog is vulnerable to xss attack");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote web application is vulnerable to an injection attack.'
  );

  script_set_attribute(
    attribute:'description',
    value:'Due to a lack of input validation, the remote version of Simple PHP
Blog can be used to perform a cross-site scripting attack by
injecting arbitrary script code to the \'q\' parameter of the
search.php script.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to a newer version or disable this software.'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/2005-04/0231.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencie("sphpblog_detect.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/sphpblog"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
 d = matches[2];
 url = string(d, "/search.php?q=<script>foo</script>");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);

 if("<b><script>foo</script></b>" >< buf )
   {
    security_warning(port:port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
   }
}
