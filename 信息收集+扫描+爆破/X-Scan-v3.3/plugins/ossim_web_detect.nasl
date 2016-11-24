#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42336);
  script_version("$Revision: 1.1 $");

  script_name(english:"OSSIM Web Frontend Detection");
  script_summary(english:"Looks for OSSIM");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The web frontend for a security suite was detected on the remote\n",
      "host."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The Open Source Security Information Management (OSSIM) web frontend\n",
      "was detected.  OSSIM is a suite of security tools used to monitor and\n",
      "maintain a network."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.alienvault.com/products.php?section=OpenSourceSIM"
  );
  script_set_attribute(
    attribute:"solution",
    value:"n/a"
  );
  script_set_attribute(
    attribute:"risk_factor",
    value:"None"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/11/02"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("http.inc");


port = get_http_port(default:80);

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/ossim", cgi_dirs()));
else dirs = make_list(cgi_dirs());

doc = '/session/login.php';

foreach dir (dirs)
{
  url = string(dir, doc);
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

  if (
    '<title> AlienVault - The Open Source SIM </title>' >< res[2] ||
    "<title> OSSIM Framework Login" >< res ||
    "<h1> OSSIM Login" >< res ||
    'alt="OSSIM logo"' >< res
  )
  {
    installs = add_install(
      appname:'ossim',
      dir:dir,
      port:port,
      installs:installs
    );
  }
  if (!isnull(installs) && !thorough_tests) break;
}

if (isnull(installs))
  exit(1, "The application wasn't detected on port "+port+".");

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'OSSIM',
    installs:installs,
    port:port,
    item:doc
  );
  security_note(port:port, extra:report);
}
else security_note(port);
