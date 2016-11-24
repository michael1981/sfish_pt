#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25443);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2007-5578");
  script_bugtraq_id(24315);
  script_xref(name:"OSVDB", value:"35243");

  script_name(english:"BASE Authentication Redirect Authentication Bypass");
  script_summary(english:"Tries to bypass authentication in BASE");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to an
authentication bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running BASE, a web-based tool for analyzing alerts
from one or more SNORT sensors. 

The version of BASE installed on the remote host allows a remote
attacker to bypass authentication to various scripts. 

Note that successful exploitation of this issue requires that BASE be
configured to use its own authentication system." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-06/0031.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb637b72" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=521723&group_id=103348" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BASE 1.3.8 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
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

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/base", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  url = string(dir, "/base_maintenance.php");

  # Check whether we get beyond the authentication check.
  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = strcat(r[0], r[1], '\r\n', r[2]);
  # There's a problem if...
  if (
    # we gain access to the main form and...
    '<FORM METHOD="POST' >< res && 'ACTION="base_maintenance.php"' >< res &&
    # Use_Auth_System is enabled
    "302 Found" >< res && egrep(pattern:"^Location: .+/index\.php", string:res)
  )
  {
    security_hole(port);
    exit(0);
  }
}
