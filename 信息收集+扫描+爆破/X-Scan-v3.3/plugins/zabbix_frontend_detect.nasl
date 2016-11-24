#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35786);
  script_version("$Revision: 1.2 $");

  script_name(english:"ZABBIX Web Interface Detection");
  script_summary(english:"Detects ZABBIX Web Interface");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a distributed monitoring system
written in PHP.");

 script_set_attribute(attribute:"description", value:
"The remote web server is running the web interface for ZABBIX, an
open source distributed monitoring system.");
 script_set_attribute(attribute:"see_also", value:"http://www.zabbix.com/");
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

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

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
if (thorough_tests) dirs = list_uniq(make_list("/zabbix", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  # Request index.phpa
  url = string(dir, "/index.php");
  res = http_get_cache(item:url, port:port);
  if (isnull(res)) exit(0);

  if (
    'href="http://www.zabbix.com/documentation.php" target="_blank">Help' >< res &&
    '<form method="post" action="index.php?login=1"' >< res
  )
  {
    # Try to extract the version number from the banner.
    ver = NULL;

    pat = 'ZABBIX ([0-9.]+)';
    matches = egrep(pattern:pat, string:res);
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

    # No release notes, so otherwise Mark as unknown.
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/zabbix"),
      value:string(ver, " under ", dir)
    );
    if (installs[ver]) installs[ver] += ';' + dir;
    else installs[ver] = dir;
  
    # Scan for multiple installations only if "Thorough Tests is checked.
  
    if (installs && !thorough_tests) break;
  }
}

# Report the findings.
if (max_index(keys(installs)))
{
  if (report_verbosity >0)
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
    if (n == 1) report += ' of the ZABBIX web interface was detected\n';
    else report += 's of the ZABBIX web interface were detected\n';
    report += 'on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
