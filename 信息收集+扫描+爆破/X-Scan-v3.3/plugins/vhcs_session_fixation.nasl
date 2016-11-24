#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25990);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-3988");
  script_bugtraq_id(25006);
  script_xref(name:"OSVDB", value:"39368");

  script_name(english:"VHCS PHPSESSID Cookie Session Fixation");
  script_summary(english:"Tries to use a fixed arbitrary session identifier");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
session fixation issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running VHCS, a control panel for hosting
providers. 

The GUI portion of the version of VHCS installed on the remote host
accepts session identifiers from GET (and likely POST) variables,
which makes it susceptible to a session fixation attack.  An attacker
may be able to exploit this issue to gain access to the affected
application using a known session identifier if he can trick a user
into logging in, say, via a specially-crafted link." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-07/0232.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
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
if (thorough_tests) dirs = list_uniq("/vhcs2", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  init_cookiejar();
  url = string(dir, "/index.php");
  # Grab index.php.
  res = http_get_cache(item:url, port:port);
  if (res == NULL) exit(0);

  # Make sure it's VHCS and that a session cookie is being set.
  if (
    ">VHCS - Virtual Hosting Control System<" >< res &&
    'action="chk_login.php" method="post"' >< res &&
    egrep(pattern:"^Set-Cookie2?:.+PHPSESSID=", string:res)
  )
  {
    # Try to exploit the flaw.
    erase_http_cookie(name: "PHPSESSID");
    r = http_send_recv3(method: "GET", 
      item:string(url, "?PHPSESSID=bc2e59c52cd7a9ae8978014e2110f203"), 
      port:port
    );
    if (isnull(r)) exit(0);

    # There's a problem if the app doesn't create another session cookie.
    if (
      ">VHCS - Virtual Hosting Control System<" >< r[2] &&
      'action="chk_login.php" method="post"' >< r[2] &&
      !egrep(pattern:"^Set-Cookie2?:.+PHPSESSID=", string:r[1])
    )
    {
      security_warning(port);
      exit(0);
    }
  }
}
