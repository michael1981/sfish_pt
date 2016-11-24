#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39537);
  script_version("$Revision: 1.3 $");

  script_name(english:"Movable Type Detection");
  script_summary(english:"Looks for evidence of Movable Type");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a weblog publishing system written in\n",
      "Perl."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote host is running Movable Type, a blog publishing system\n",
      "written in Perl."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.movabletype.com/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"n/a"
  );
  script_set_attribute(
    attribute:"risk_factor",
    value:"None"
  );
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


port = get_http_port(default:80, embedded: 0);

if (thorough_tests)
  dirs = list_uniq(make_list("/mt", "/cgi-bin/mt", "/blog", cgi_dirs()));
else
  dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  # If an install needs to be updated, /mt.cgi redirects to /mt-update.cgi.
  # Specifying the logout mode seems to prevent this.
  url = string(dir, '/mt.cgi?__mode=logout');
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(1, "The web server is not responding.");

  if (
    'mt.cgi"><img alt="Movable Type"' >< res[2] ||    # MT version 3
    'Movable Type</title>' >< res[2]                  # MT version 4
  )
  {
    pattern = '/mt.js\\?v=([0-9.]+)"></script>';
    match = eregmatch(string:res[2], pattern:pattern, icase:TRUE);

    if (match) ver = match[1];
    else ver= 'unknown';

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/movabletype"),
      value:string(ver, " under ", dir)
    );
    if (installs[ver]) installs[ver] += ';' + dir;
    else installs[ver] = dir;

    # Scan for multiple installations only if "Thorough Tests" is checked.
    if (installs && !thorough_tests) break;
  }
}


# Report findings.
if (max_index(keys(installs)))
{
  if (report_verbosity > 0)
  {
    info = "";
    n = 0;
    foreach ver (sort(keys(installs)))
    {
      info += '  Version : ' + ver + '\n';
      foreach dir (sort(split(installs[ver], sep:";", keep:FALSE)))
      {
        if (dir == '/') url = dir;
        else url = dir + '/';
        info += '  URL     : ' + build_url(port:port, qs:url) + ' \n';
        n++;
      }
      info += '\n';
    }

    report = '\nThe following instance';
    if (n == 1) report += ' of Movable Type was';
    else report += 's of Movable Type were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);

  exit(0);
}

