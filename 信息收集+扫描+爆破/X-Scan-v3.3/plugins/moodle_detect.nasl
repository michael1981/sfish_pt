#
# (C) Tenable Network Security
# 



include("compat.inc");

if (description)
{
  script_id(18690);
  script_version("$Revision: 1.6 $");

  script_name(english:"Moodle Detection");
  script_summary(english:"Detects Moodle");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a content management system written in
PHP." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Moodle, an open-source content management
system written in PHP." );
 script_set_attribute(attribute:"see_also", value:"http://moodle.org/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
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
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/moodle", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  # Request index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If it looks like Moodle...
  if (egrep(string:res, pattern:'<a [^>]*href="http://moodle\\.org/"[^>]*><img [^>]*src="pix/moodlelogo.gif"'))
  {
    ver = NULL;

    # Try to extract the version number from the banner.
    pat = '<a title="moodle ([0-9][^"]+)" href="http://moodle\\.org/"';
    if (egrep(string:res, pattern:pat, icase:TRUE))
    {
      matches = egrep(pattern:pat, string:res, icase:TRUE);
      if (matches)
      {
        foreach match (split(matches, keep:FALSE))
        {
          item = eregmatch(pattern:pat, string:match, icase:TRUE);
          if (!isnull(item))
          {
            ver = item[1];
            break;
          }
        }
      }
    }

    # If that didn't work, try to get it from the release notes.
    if (isnull(ver))
    {
      url = string(dir, "/lang/en/docs/release.html");
      res = http_send_recv3(method:"GET", item:url, port:port);
      if (isnull(res)) exit(0);

      # nb: ignore patterns like "Moodle 1.5 (to be released shortly)"
      pat = "^<h2>Moodle (.+) \([0-9]";
      if (egrep(string:res[2], pattern:pat, icase:TRUE))
      {
        matches = egrep(pattern:pat, string:res, icase:TRUE);
        if (matches)
        {
          foreach match (split(matches, keep:FALSE))
          {
            item = eregmatch(pattern:pat, string:match, icase:TRUE);
            if (!isnull(item))
            {
              ver = item[1];
              break;
            }
          }
        }
      }
    }

    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/moodle"),
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
  if (report_verbosity)
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
        info += '  URL     : ' + build_url(port:port, qs:url) + '\n';
        n++;
      }
      info += '\n';
    }

    report = '\nThe following instance';
    if (n == 1) report += ' of Moodle was';
    else report += 's of Moodle were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
