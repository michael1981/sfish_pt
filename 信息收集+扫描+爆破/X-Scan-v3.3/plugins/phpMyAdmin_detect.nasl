#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(17219);
  script_version("$Revision: 1.15 $");
 
  script_name(english:"phpMyAdmin Detection");
  script_summary(english:"Looks for phpMyAdmin's main.php");
 
  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a database management application\n",
      "written in PHP."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running phpMyAdmin, a web-based MySQL\n",
      "administration tool written in PHP."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/index.php"
  );
  script_set_attribute(
   attribute:"solution",
   value:string(
    "Make sure the use of this program is in accordance with your corporate\n",
    "security policy."
   )
  );

  script_set_attribute(
    attribute:"risk_factor",
    value:"None"
  );
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
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
if (thorough_tests) dirs = list_uniq(make_list("/phpMyAdmin", "/phpmyadmin", "/pma", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  url = string(dir, "/main.php");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  pat = "^.*(Welcome to .*phpMyAdmin ([0-9]+\.[^<]+)?<.*/h[12]>|parent\.document\.title = .+phpMyAdmin ([0-9]+\.[^']+)';)";
  matches = egrep(pattern:pat, string:res[2]);
  if (matches)
  {
    ver = NULL;

    # First, try to get the version from main.php
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:match, icase:TRUE);
      if (!isnull(item))
      {
        if ("parent.document" >< match) ver = item[3];
        else ver = item[2];
        break;
      }
    }

    # If the version wasn't found, try to get it from Documentation.html
    if (!isnull(ver))
    {
      ver = chomp(ver);
    }
    else
    {
      url2 = string(dir, "/Documentation.html");
      res2 = http_send_recv3(method:"GET", item:url2, port:port);
      if (isnull(res2)) exit(0);

      pat = '<title>phpMyAdmin ([^ ]+) - Documentation</title>';
      ver_match = eregmatch(pattern:pat, string:res2[2], icase:TRUE);
      if(ver_match) ver = ver_match[1];
    }

    # If the ver's _still_ unknown, we'll still record the install in the kb
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/phpMyAdmin"), 
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
    if (n == 1) report += ' of phpMyAdmin was';
    else report += 's of phpMyAdmin were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
