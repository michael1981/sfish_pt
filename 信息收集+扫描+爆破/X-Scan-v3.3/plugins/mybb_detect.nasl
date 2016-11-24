#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(20841);
  script_version("$Revision: 1.6 $");

  script_name(english:"MyBB Detection");
  script_summary(english:"Checks for presence of MyBB");
 
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server contains a bulletin board system written in PHP."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running MyBB (formerly known as MyBulletinBoard), a\n",
      "web-based bulletin board system written in PHP and using MySQL for its\n",
      "back-end storage."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://mybboard.net/"
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
 
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
 
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP scripts.");


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/mybb", "/forum", "/forums", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

  # If it's MyBB.
  if (egrep(pattern:"Powered [bB]y <[^>]+>My(BB|BulletinBoard)</", string:res))
  {
    # Try to identify the version number from index.php.
    #
    # nb: don't put much trust in this -- the vendor habitually
    #     releases patches that do not update the version number.
    ver = NULL;

    pat = "Powered [bB]y <[^>]+>My(BB|BulletinBoard)</a> ([^<]+)<br />";
    matches = egrep(pattern:pat, string:res);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          ver = item[2];
          break;
        }
      }
    }

    # If still unknown, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/mybb"),
      value:string(ver, " under ", dir)
    );
    if (installs[ver]) installs[ver] += ';' + dir;
    else installs[ver] = dir;

    # Scan for multiple installations only if "Thorough Tests" is checked.
    if (!thorough_tests) break;
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
        info += '  URL     : ' + build_url(port:port, qs:dir+'/') + '\n';
        n++;
      }
      info += '\n';
    }

    report = '\nThe following instance';
    if (n == 1) report += ' of MyBB was';
    else report += 's of MyBB were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
