#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(18133);
  script_version("$Revision: 1.9 $");

  script_name(english:"Horde Mnemo Detection");
  script_summary(english:"Checks for presence of Mnemo");
 
  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a note manager written in PHP."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running Mnemo, an open source PHP-based note\n",
      "manager from the Horde Project."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.horde.org/mnemo/"
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

  script_dependencies("horde_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server does not support PHP.");


# Horde is a prerequisite.
horde_install = get_kb_item(string("www/", port, "/horde"));
if (isnull(horde_install)) exit(1, "The 'www/"+port+"/horde' KB item is missing.");
matches = eregmatch(string:horde_install, pattern:"^(.+) under (/.*)$");
if (isnull(matches)) exit(0);
horde_dir = matches[2];


# Search for version number in a couple of different pages.
files = make_list(
  "/services/help/?module=mnemo&show=menu",
  "/services/help/?module=mnemo&show=about",
  "/docs/CHANGES", "/lib/version.phps"
);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/mnemo", horde_dir+"/mnemo", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (isnull(res)) exit(1, "The web server failed to respond.");

  # If we're redirected to a login page...
  #
  # nb: Horde itself redirects to a login page but without the 'url' parameter.
  if (egrep(pattern:"^Location: .*/login\.php\?url=", string:res))
  {
    version = NULL;

    foreach file (files)
    {
      # Get the page.
      if ("/services/help" >< file) url = horde_dir + file;
      else url = dir + file;

      res = http_send_recv3(method:"GET", item:url, port:port);
      if (isnull(res)) exit(0);

      # Specify pattern used to identify version string.
      #
      # - version 2.1
      if ("show=menu" >< file)
      {
        pat = ">Mnemo H[0-9]+ \(([0-9]+\.[^<]+)\)</span>";
      }
      # - version 2.0
      else if ("show=about" >< file)
      {
        pat = '>This is Mnemo +(.+)\\.<';
      }
      # - version 1.x
      else if (file == "/docs/CHANGES")
      {
        pat = "^ *v([0-9]+\..+) *$";
      }
      #   nb: another security risk -- ability to view PHP source.
      else if (file == "/lib/version.phps")
      {
        pat = "MNEMO_VERSION', '(.+)'";
      }
      # - someone updated files but forgot to add a pattern???
      else
      {
        exit(1, strcat("don't know how to handle file '", file));
      }

      # Get the version string.
      matches = egrep(pattern:pat, string:res[2]);
      if (
        matches &&
        (
          # nb: add an extra check in the case of the CHANGES file.
          (file == "/docs/CHANGES" && "Mnemo " >< res[2]) ||
          file != "/docs/CHANGES"
        )
      )
      {
        foreach match (split(matches, keep:FALSE))
        {
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            version = item[1];
            break;
          }
        }
      }

      # If the version is known...
      if (!isnull(version))
      {
        if (dir == "") dir = "/";
        set_kb_item(
          name:string("www/", port, "/horde_mnemo"),
          value:string(version, " under ", dir)
        );
        if (installs[version]) installs[version] += ';' + dir;
        else installs[version] = dir;

        break;
      }
    }
  }
  # Scan for multiple installations only if "Thorough Tests" is checked.
  if (max_index(keys(installs)) && !thorough_tests) break;
}


# Report findings.
if (max_index(keys(installs)))
{
  if (report_verbosity > 0)
  {
    info = "";
    n = 0;
    foreach version (sort(keys(installs)))
    {
      info += '  Version : ' + version + '\n';
      foreach dir (sort(split(installs[version], sep:";", keep:FALSE)))
      {
        if (dir == '/') url = dir;
        else url = dir + '/';
        info += '  URL     : ' + build_url(port:port, qs:url) + '\n';
        n++;
      }
      info += '\n';
    }

    report = '\nThe following instance';
    if (n == 1) report += ' of Mnemo was';
    else report += 's of Mnemo were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
