#
# (C) Tenable Network Security
#



include("compat.inc");

if (description)
{
  script_id(18613);
  script_version("$Revision: 1.7 $");

  script_name(english:"XOOPS Detection");
  script_summary(english:"Detects XOOPS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a content management system written in
PHP." );
 script_set_attribute(attribute:"description", value:
"The remote host is running XOOPS, a web content management system
written in PHP and released under the GPL." );
 script_set_attribute(attribute:"see_also", value:"http://www.xoops.org/" );
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
if (!can_host_php(port:port)) exit(0);


# Search for XOOPS.
if (thorough_tests) dirs = list_uniq(make_list("/xoops", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  # Grab lostpass.php.
  url = string(dir, "/lostpass.php");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  # If it looks like XOOPS...
  if ('<meta http-equiv="Refresh" content="2; url=user.php?xoops_redirect=' >< res[2])
  {
    # Try to identify the version number.
    ver = NULL;

    url = string(dir, "/modules/news/index.php");
    res = http_send_recv3(method:"GET", item:url, port:port);
    if (isnull(res)) exit(0);

    pat = "/modules/news/article\.php\?storyid=([0-9]+)";
    matches = egrep(pattern:pat, string:res[2], icase:TRUE);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          id = item[1];

          # Try to request a printer-friendly formatted version.
          url = string(dir, "/modules/news/print.php?storyid=", id);
          res = http_send_recv3(method:"GET", item:url, port:port);
          if (isnull(res)) exit(0);

          pat = '<meta name="GENERATOR" content="XOOPS ([0-9][^"]+)"';
          matches = egrep(pattern:pat, string:res[2], icase:TRUE);
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

          # nb: we only need one story id.
          break;
        }
      }
    }

    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/xoops"),
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
    if (n == 1) report += ' of XOOPS was';
    else report += 's of XOOPS were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
