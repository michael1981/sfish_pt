#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34373);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2008-6163");
  script_bugtraq_id(31549);
  script_xref(name:"milw0rm", value:"6655");
  script_xref(name:"OSVDB", value:"48756");
  script_xref(name:"Secunia", value:"32114");

  script_name(english:"OpenX ac.php bannerid Parameter SQL Injection");
  script_summary(english:"Checks if bannerid parameter is sanitized");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running OpenX (formerly Openads), an open source ad
serving application written in PHP. 

The installed version of OpenX does not validate user-supplied input
to the 'bannerid' parameter of the 'www/delivery/ac.php' script before
using it in database queries.  Regardless of PHP's 'magic_quotes_gpc'
setting, an unauthenticated remote attacker can leverage this issue to
manipulate SQL queries and, for example, uncover sensitive information
from the application's database or possibly execute arbitrary PHP
code." );
 script_set_attribute(attribute:"see_also", value:"http://www.openx.org/docs/2.4/release-notes/openx-2.4.9" );
 script_set_attribute(attribute:"see_also", value:"http://www.openx.org/docs/2.6/release-notes/openx-2.6.2" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/497111/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenX version 2.4.9 / 2.6.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/openx", "/openads", "/ads", "/adserver", cgi_dirs()));
else dirs = make_list(cgi_dirs());

info = "";
foreach dir (dirs)
{
  # Try to exploit the issue so we get an ad of some type.
  exploit = string("-", rand() % 1000, " OR 1=1");
  url = string(
    dir, "/www/delivery/ac.php?",
    "bannerid=", str_replace(find:" ", replace:"+", string:exploit)
  );

  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # If we see an ad...
  if ("www/delivery/ck.php?oaparams=" >< res)
  {
    # Try to exploit the issue so we don't get an ad.
    exploit = str_replace(find:"1=1", replace:"1=0", string:exploit);
    url = string(
      dir, "/www/delivery/ac.php?",
      "bannerid=", str_replace(find:" ", replace:"+", string:exploit)
    );

    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (res == NULL) exit(0);

    # There's a problem if we don't see an ad this time.
    if (
      "title>Advertisement" >< res && 
      "www/delivery/ck.php?oaparams=" >!< res
    )
    {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
