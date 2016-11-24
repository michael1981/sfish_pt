#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24874);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-1647");
  script_xref(name:"milw0rm", value:"3508");
  script_xref(name:"OSVDB", value:"43558");

  script_name(english:"Moodle moodledata/sessions/ Session Files Remote Information Disclosure");
  script_summary(english:"Checks whether moodledata is accessible");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Moodle on the remote host allows a remote attacker to
browse session files, which likely contain sensitive information about
users of the application, such as password hashes and email addresses." );
 script_set_attribute(attribute:"see_also", value:"http://docs.moodle.org/en/Configuration_file" );
 script_set_attribute(attribute:"solution", value:
"Either configure the web server to prevent directory listing or
configure the application so its 'dataroot' is located outside the web
server's documents directory." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("moodle_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/moodle"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  init_cookiejar();
  # Get the session id.
  r = http_send_recv3(method: "GET", item:string(dir, "/index.php"), port:port);
  if (isnull(r)) exit(0);

  sid = get_http_cookie(name: "MoodleSession");
  # If we have a session cookie...
  if (!isnull(sid))
  {
    # Try to exploit the flaw.
    r = http_send_recv3(method: "GET", item:string(dir, "/moodledata/sessions/"), port:port);
    if (isnull(r)) exit(0);

    # There's a problem if our session file shows up in the listing.
    if (string('href="sess_', sid, '">sess_') >< r[2])
      security_warning(port);
  }
}
