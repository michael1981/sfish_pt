#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38648);
  script_version("$Revision: 1.2 $");

  script_name(english:"Atmail WebMail Detection");
  script_summary(english:"Looks for the Atmail WebMail login page");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server contains a PHP application used for webmail."
  );
  script_set_attribute(
    attribute:"description",
    value:"Atmail WebMail is installed on the remote web server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.atmail.com/linux-email-server/"
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Ensure use of the software confirms with your organization's\n",
      "acceptable use and security policies."
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


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/mail", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  # Try to pull up the login page.
  url = string(dir, "/index.php");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  if (">Powered by Atmail " >< res[2])
  {
    ver = NULL;
    pattern = ">Powered by Atmail ((demo )?[0-9]+\.[^<]+)</a>";
    match = eregmatch(pattern:pattern, string:res[2], icase:TRUE);

    # If this doesn't look like Atmail, move on to the next dir
    if (match) ver = match[1];

    # If the ver's still unknown, we'll still record the install in the KB.
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/atmail_webmail"), 
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
    if (n == 1) report += ' of Atmail was';
    else report += 's of Atmail were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
