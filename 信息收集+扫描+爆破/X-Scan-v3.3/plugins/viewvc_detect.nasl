#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42347);
  script_version("$Revision: 1.1 $");

  script_name(english:"ViewVC Detection");
  script_summary(english:"Looks for ViewVC");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server is running a version control repository browser\n",
      "written in Python."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote host is running ViewVC, a web-based tool for browsing CVS\n",
      "and Subversion repositories."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.viewvc.org/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"n/a"
  );
  script_set_attribute(
    attribute:"risk_factor",
    value:"None"
  );
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80);

installs = NULL;
pattern = '<meta name="generator" content="ViewVC ([0-9.]+)" />';
dirs = cgi_dirs();

# The ViewVC INSTALL file has instructions for serving the app out the
# following locations
if (thorough_tests)
{
  dirs = make_list(dirs, '/viewvc', '/cgi-bin/viewvc.cgi', '/viewvc.cgi');
  dirs = list_uniq(dirs);
}

foreach dir (dirs)
{
  url = string(dir, '/');
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

  match = eregmatch(string:res[2], pattern:pattern, icase:TRUE);
  if (match)
  {
    installs = add_install(
      installs:installs,
      dir:dir,
      ver:match[1],
      appname:'viewvc',
      port:port
    );

    if (!thorough_tests) break;
  }
}

if (isnull(installs)) exit(1, "ViewVC wasn't detected on port "+port+".");

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'ViewVC',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
