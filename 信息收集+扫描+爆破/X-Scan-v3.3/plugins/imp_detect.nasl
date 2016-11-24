#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#



include("compat.inc");

if (description)
{
  script_id(12643);
  script_version("$Revision: 1.20 $");
 
  script_name(english:"IMP Software Detection");
  script_summary(english:"Checks for the presence of IMP");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a webmail client." );
 script_set_attribute(attribute:"description", value:
"The remote host is running IMP, an open source PHP-based webmail
package from The Horde Project that provides access to mail accounts
via POP3 or IMAP." );
 script_set_attribute(attribute:"see_also", value:"http://www.horde.org/imp/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2009 George A. Theall");

  script_dependencies("horde_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Horde is a prerequisite.
horde_install = get_kb_item(string("www/", port, "/horde"));
if (isnull(horde_install)) exit(0);
matches = eregmatch(string:horde_install, pattern:"^(.+) under (/.*)$");
if (isnull(matches)) exit(0);
horde_dir = matches[2];


# Search for version number in a couple of different pages.
files = make_list(
  "/services/help/?module=imp&show=menu",
  "/services/help/?module=imp&show=about",
  "/docs/CHANGES", "/test.php", "/lib/version.phps",
  "/status.php3"
);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/webmail", "/imp", horde_dir+"/imp", "/email", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (isnull(res)) exit(1, "The web server failed to respond.");

  # If we see the copyright...
  if ("IMP: Copyright 20" >< res)
  {
    version = NULL;

    foreach file (files)
    {
      # Get the page.
      if ("/services/help" >< file) url = horde_dir + file;
      else url = dir + file;

      req = http_get(item:url, port:port);
      res = http_keepalive_send_recv(port:port, data:req);
      if (isnull(res)) exit(1, "The web server failed to respond.");

      # Specify pattern used to identify version string.
      # - version 4.1
      if ("show=menu" >< file)
      {
        pat = ">IMP H[0-9]+ \(([0-9]+\.[^<]+)\)</span>";
      }
      # - version 4.0
      else if ("show=about" >< file)
      {
        pat = ">This is Imp (.+)\.<";
      }
      # - version 3.x
      else if (file == "/docs/CHANGES")
      {
        pat = "^ *v([0-9]+\..+) *$";
      }
      #   nb: test.php available is itself a vulnerability but sometimes available.
      else if (file == "/test.php")
      {
        pat = "^ *<li>IMP: +(.+) *</li> *$";
      }
      #   nb: another security risk -- ability to view PHP source.
      else if (file == "/lib/version.phps")
      {
        pat = "IMP_VERSION', '(.+)'";
      }
      # - version 2.x
      else if (file == "/status.php3")
      {
        pat = ">IMP, Version (.+)<";
      }
      # - someone updated files but forgot to add a pattern???
      else
      {
        exit(1, strcat("don't know how to handle file '", file));
      }

      matches = egrep(pattern:pat, string:res);
      if (
        matches &&
        (
          # nb: add an extra check in the case of the CHANGES file.
          (file == "/docs/CHANGES" && "IMP " >< res) ||
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
          name:string("www/", port, "/imp"), 
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
    if (n == 1) report += ' of IMP was';
    else report += 's of IMP were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
