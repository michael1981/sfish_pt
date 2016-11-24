#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(18638);
  script_version("$Revision: 1.9 $");

  script_name(english:"Drupal Software Detection");
  script_summary(english:"Detects Drupal");
 
  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a content management system written in\n",
      "PHP."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running Drupal, an open-source content management\n",
      "system written in PHP."
    )
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
 

  script_set_attribute(
    attribute:"see_also", 
    value:"http://drupal.org/"
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
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/drupal", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  # Grab update.php.
  url = string(dir, "/update.php?op=info");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  # If it looks like Drupal...
  if (
    (
      "main Drupal directory" >< res[2] && 
      (
        "<code>$access_check = FALSE;</code>" >< res[2] ||
        "<code>$update_free_access = FALSE;</code>" >< res[2]
      )
    ) ||
    "<h1>Drupal database update</h1>" >< res[2]
  )
  {
    ver = NULL;

    # Try to identify the version number from the changelog.
    url = string(dir, "/CHANGELOG.txt");
    res = http_send_recv3(method:"GET", item:url, port:port);
    if (isnull(res)) exit(0);

    # nb: Drupal 1.0.0 was the first version, released 2001-01-15.
    pat = "^Drupal +([1-9].+), 20";
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

    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/drupal"),
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
    if (n == 1) report += ' of Drupal was';
    else report += 's of Drupal were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
