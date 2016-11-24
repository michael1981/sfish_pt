#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(30109);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-0491");
  script_bugtraq_id(27464);
  script_xref(name:"OSVDB", value:"40916");

  script_name(english:"WordPress fGallery fim_rss.php album Parameter SQL Injection");
  script_summary(english:"Tries to generate a SQL syntax error");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running fGallery, a third-party image gallery
plugin for WordPress. 

The version of fGallery installed on the remote host fails to sanitize
input to the 'album' parameter of the 'fim_rss.php' script before
using it in a database query.  Regardless of PHP's 'magic_quotes_gpc'
setting, an attacker may be able to exploit this issue to manipulate
database queries, leading to disclosure of sensitive information,
modification of data, or attacks against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4845" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/wordpress"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the issue to generate a SQL syntax error.
  exploit = string("-1 ", SCRIPT_NAME, " -- ");

  req = http_get(
    item:string(
      dir, "/wp-content/plugins/fgallery/fim_rss.php?",
      "album=", urlencode(str:exploit)
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see a syntax error.
  if (string("fim_cat WHERE id = ", exploit, "</code>") >< res)
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
