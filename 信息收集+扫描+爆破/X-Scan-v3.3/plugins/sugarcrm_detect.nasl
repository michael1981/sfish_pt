#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description) {
  script_id(19496);
  script_version("$Revision: 1.9 $");

  script_name(english:"SugarCRM Detection");
  script_summary(english:"Checks for presence of SugarCRM");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server contains a CRM system written in PHP."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running SugarCRM, a customer relationship\n",
      "management (CRM) application written in PHP."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.sugarcrm.com/"
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

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

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


# Search for SugarCRM
if (thorough_tests) dirs = list_uniq(make_list("/sugarcrm", "/sugar", "/SugarCRM", cgi_dirs()));
else dirs = make_list(cgi_dirs());

login_page = '/index.php?action=Login&module=Users';
installs = 0;
foreach dir (dirs) {
  # Grab index.php.
  res = http_get_cache(item:string(dir, login_page), port:port);
  if (res == NULL) exit(0);

  # If it looks like SugarCRM...
  if (
    "<!--SugarCRM - Commercial Open Source CRM-->" >< res ||
    "alt='Powered By SugarCRM'>" >< res
  ) {
    # Try to grab the version number from README.txt - Sugar only 
    # displays it normally to logged-in users.
    url = string(dir, "/README.txt");
    res = http_send_recv3(method:"GET", item:url, port:port);
    if (isnull(res)) exit(0);

    pat = "^Sugar Suite v([0-9].+)$";
    matches = egrep(pattern:pat, string:res[2]);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];
          break;
        }
      }
    }

    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/sugarcrm"),
      value:string(ver, " under ", dir)
    );

    if (installations[ver]) installations[ver] += ';' + dir;
    else installations[ver] = dir;
    ++installs;

    # Scan for multiple installations only if "Thorough Tests" is checked.
    if (!thorough_tests) break;
  }
}


# Report any instances found unless Report verbosity is "Quiet".
if (installs && report_verbosity > 0) {
  info = "";

  foreach version (sort(keys(installations)))
  {
    info += '\n  Version : ' + version + '\n';

    foreach dir (sort(split(installations[version], sep:";", keep:FALSE)))
    {
      if (dir == '/') url = login_page;
      else url = dir + login_page;

      info += '  URL     : ' + build_url(port:port, qs:url) + '\n';
      n++;
    }
  }

  report = '\nThe following instance';
  if (installs == 1) report += ' of SugarCRM was';
  else report += 's of SugarCRM were';
  report += ' detected on the remote host :\n' + info;

  security_note(port:port, extra:info);
}
