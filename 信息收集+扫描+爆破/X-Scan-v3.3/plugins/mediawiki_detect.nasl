#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(19233);
  script_version("$Revision: 1.6 $");

  script_name(english:"MediaWiki Detection");
  script_summary(english:"Detects MediaWiki");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server contains a wiki application written in PHP."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running MediaWiki, an open-source wiki application\n",
      "written in PHP."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://wikipedia.sourceforge.net/"
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

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server does not support PHP scripts.");


# Search for MediaWiki.
if (thorough_tests) dirs = list_uniq(make_list("/wiki", "/Wiki", "/mediawiki", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  # Request index.php and try to get the version number.
  url = string(dir, "/index.php?title=Special:Version");

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  # If it looks like MediaWiki...
  if ('<div id="f-poweredbyico"><a href="http://www.mediawiki.org/">' >< res[2])
  {
    version = NULL;

    # It may appear as a table element.
    if (
      'id="mw-version-software">' >< res[2] &&
      'rel="nofollow">MediaWiki</a></td>' >< res[2]
    )
    {
      element = strstr(res[2], 'rel="nofollow">MediaWiki</a></td>');
      element = element - strstr(element, '</tr>');
      if ('MediaWiki</a></td>' >< element)
        element = strstr(element, 'MediaWiki</a></td>') - 'MediaWiki</a></td>';
      pat = "<td> *([0-9]+\.[0-9]+.*) *</td>";
      matches = egrep(pattern:pat, string:element);
      if (matches)
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
    }

    if (isnull(version))
    {
      # nb: the installation may require authentication, but the
      #     page will at least clue us in to MediaWiki's presence.
      #
      # nb: this doesn't catch the really old versions (MediaWiki-stable 
      #     20031117 and older), but they no longer appear to be deployed.
      pat = ">MediaWiki</a>[^: ]*: ([0-9]+\.[0-9]+.*)";
      matches = egrep(pattern:pat, string:res);
      if (matches)
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
    }

    # If that didn't work, try to get it from the release notes.
    if (isnull(version))
    {
      url = string(dir, "/RELEASE-NOTES");

      res = http_send_recv3(method:"GET", item:url, port:port);
      if (isnull(res)) exit(0);

      pat = "^== MediaWiki ([0-9]+\.[0-9]+.*) ==";
      matches = egrep(pattern:pat, string:res);
      if (matches)
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
    }

    # Oh well, just mark it as "unknown".
    if (isnull(version)) version = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/mediawiki"),
      value:string(version, " under ", dir)
    );
    if (installs[version]) installs[version] += ';' + dir;
    else installs[version] = dir;

    # Scan for multiple installations only if "Thorough Tests" is checked.
    if (!thorough_tests) break;
  }
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
    if (n == 1) report += ' of MediaWiki was';
    else report += 's of MediaWiki were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
