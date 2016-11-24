#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18297);
  script_version("$Revision: 1.13 $");

  script_name(english:"WordPress Detection");
  script_summary(english:"Checks for presence of WordPress");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a blog application written in PHP." );
 script_set_attribute(attribute:"description", value:
"The remote host is running WordPress, a free blog application written
in PHP and with a MySQL back-end." );
 script_set_attribute(attribute:"see_also", value:"http://www.wordpress.org/" );
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
if (thorough_tests) dirs = list_uniq(make_list("/wordpress", "/blog", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/"), port:port);
  if (isnull(res)) exit(0);

  if (strlen(res) > 2048) subres = substr(res, 0, 2048);
  else subres = res;

  # Try to identify the version number from the Generator meta tag.
  pat = '<meta name="generator" content="WordPress (.+)" />';
  matches = egrep(pattern:pat, string:subres);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        ver = item[1];
        break;
      }
    }

    # If that didn't work, look in readme.html.
    if (isnull(ver))
    {
      url = string(dir, "/readme.html");
      res = http_send_recv3(method:"GET", item:url, port:port);
      if (isnull(res)) exit(0);

      pat = "^ +Version ([^<]+)</h1>";
      matches = egrep(pattern:pat, string:res[2]);
      if (matches)
      {
        foreach match (split(matches, keep:FALSE))
        {
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            ver = item[1];
            break;
          }
        }
      }
    }

    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/wordpress"),
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
        if (dir == '/') url = dir;
        else url = dir + '/';
        info += '  URL     : ' + build_url(port:port, qs:url) + '\n';
        n++;
      }
      info += '\n';
    }

    report = '\nThe following instance';
    if (n == 1) report += ' of WordPress was';
    else report += 's of WordPress were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
