#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25291);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2007-2821");
  script_bugtraq_id(24076);
  script_xref(name:"OSVDB", value:"36311");

  script_name(english:"WordPress check_ajax_referer() Function SQL Injection");
  script_summary(english:"Tries to generate a SQL error");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The version of WordPress on the remote host fails to properly sanitize
input to the 'cookie' parameter of the 'wp-admin/admin-ajax.php'
script before using it in the 'check_ajax_referer' function in
database queries.  Regardless of PHP's 'magic_quotes_gpc' setting, an
unauthenticated remote attacker can leverage this issue to launch SQL
injection attacks against the affected application, including
discovery of password hashes of WordPress users." );
 script_set_attribute(attribute:"see_also", value:"http://www.waraxe.us/advisory-50.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/3960" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-05/0319.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/wordpress"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  # Try to exploit the flaw to generate a SQL error.
  exploit = string("'", SCRIPT_NAME);
  # nb: this works as long as the USER_COOKIE and PASS_COOKIE are
  #     derived from COOKIEHASH / site url as in wp-settings.php.
  site = string("http://", get_host_name());
  if (port != 80) site = string(site, ":", port);
  if (dir[strlen(dir)-1] == '/') dir = substr(dir, 0, strlen(dir)-2);
  site = string(site, dir);
  cookiehash = hexstr(MD5(site));

  # nb: we need to encode (twice) the single quote.
  cookie = urlencode(
    str        : exploit,
    unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!~*()-]/"
  );
  cookie = string(
    "wordpressuser_", cookiehash, "=", cookie, "; ",
    "wordpresspass_", cookiehash, "=x"
  );

  u = string(dir, "/wp-admin/admin-ajax.php?",
      "cookie=", urlencode(str:cookie));
  r = http_send_recv3(method: "GET", port:port, item: u);
  if (isnull(r)) exit(0);

  # There's a problem if we see an error involving our exploit for the user name.
  if ("WordPress database error" >< r[2])
  {
    res2 = str_replace(find:"&#039;", replace:"'", string:r[2]);
    if (string(" WHERE user_login = '", exploit, "'</code>") >< res2)
    {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
