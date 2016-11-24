#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29802);
  script_version("$Revision: 1.6 $");

  script_bugtraq_id(27010);
  script_xref(name:"OSVDB", value:"39888");

  script_name(english:"CuteNews search.php files_arch Array Arbitrary File Access");
  script_summary(english:"Adds a nonexistent file to files_arch");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure issue." );
 script_set_attribute(attribute:"description", value:
"The version of CuteNews on the remote host fails to initialize the
'files_arch[]' array before populating it with a list of files to
search in the 'search.php' script.  Regardless of PHP's
'register_globals' setting, an unauthenticated attacker can leverage
this issue to determine the existence of arbitrary files on the
affected host or search files for arbitrary text, such as usernames
and password hashes defined to the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/485485/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4779" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("cutenews_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/cutenews"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the flaw to simply generate an error message.
  arch = SCRIPT_NAME;

  r = http_send_recv3(method:"GET", port: port,
    item:string(dir, "/search.php?",
      "dosearch=yes&",
      "files_arch[]=", arch));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if 
  if (
    string("file(", arch, "): failed to open stream") >< res ||
    string("file(", arch, ") [function.file]: failed to open stream") >< res
  )
  {
    security_warning(port);
    exit(0);
  }
}
