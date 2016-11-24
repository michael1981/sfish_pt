#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(29835);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-0129");
  script_bugtraq_id(27120);
  script_xref(name:"OSVDB", value:"40197");

  script_name(english:"Site@School slideshow_full.php album_name Parameter SQL Injection");
  script_summary(english:"Tries to generate a SQL syntax error");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Site@School, an open-source, PHP-based,
content management system intended for primary schools. 

The version of this software installed on the remote host fails to
sanitize user-supplied input to the 'album_name' parameter of the
'starnet/addons/slideshow_full.php' script before using it in a
database query.  Provided PHP's 'magic_quotes_gpc' setting is
disabled, an attacker may be able to exploit this issue to manipulate
database queries, leading to disclosure of sensitive information,
modification of data, or attacks against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4832" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
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
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
foreach dir (cgi_dirs())
{
  # Try to exploit the issue.
  magic = rand();
  exploit = string("'", magic);

  req = http_get(
    item:string(
      dir, "/starnet/addons/slideshow_full.php?",
      "album_name=", urlencode(str:exploit)
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see our exploit in the query.
  if (string(exploit, "'' at line 1SELECT id, description, children ") >< res)
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
