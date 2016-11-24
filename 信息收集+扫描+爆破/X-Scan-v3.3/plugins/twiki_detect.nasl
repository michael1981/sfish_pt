#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(19941);
  script_version("$Revision: 1.11 $");

  script_name(english:"TWiki Detection");
  script_summary(english:"Checks for presence of TWiki");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Wiki system written in Perl." );
 script_set_attribute(attribute:"description", value:
"he remote host is running TWiki, an open-source wiki system written in
Perl." );
 script_set_attribute(attribute:"see_also", value:"http://twiki.org/" );
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

# Search through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/twiki/bin", "/wiki/bin", "/cgi-bin/twiki", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  # Try to get the TWiki Web home page.
  w = http_send_recv3(method:"GET", item:string(dir, "/view/TWiki/WebHome"), port:port);
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # If it looks like TWiki...
  if (
    ' alt="This site is powered by the TWiki' >< res ||
    ' alt="This site is powered by the TWiki' >< res ||
    '<div class="twikiMain"><div class="twikiToolBar"><div>' >< res ||
    '/view/TWiki/WebHome?skin=print.pattern">' >< res ||
    'class="twikiFirstCol">' >< res
  ) {
    # Try to pull out the version number.
    ver = NULL;

    pat = "<li> This site is running TWiki version <strong>([^<]+)</strong>";
    matches = egrep(pattern:pat, string:res);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];
          break;
        }
      }
    }

    # If that didn't work, look in TWikiHistory.html.
    if (isnull(ver)) {
      w = http_send_recv3(method:"GET", item:string(dir, "/view/TWiki/TWikiHistory"), port:port);
      if (isnull(w)) exit(1, "the web server did not answer");
      res = w[2];

      pat = '<li> <a href="#.*Release[^"]*">([^<]+)<';
      matches = egrep(pattern:pat, string:res);
      if (matches) {
        foreach match (split(matches)) {
          match = chomp(match);
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item)) {
            ver = item[1];
            if ("TWiki Release " >< ver) ver = strstr(ver, "TWiki Release ") - "TWiki Release ";
            ver = str_replace(string:ver, find:"-", replace:" ");

            # releases are listed reverse chronologically; we want only the first.
            break;
          }
        }
      }
    }

    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/twiki"),
      value:string(ver, " under ", dir)
    );
    installations[dir] = ver;
    ++installs;

    # Scan for multiple installations only if "Thorough Tests" is checked.
    if (!thorough_tests) break;
  }
}


# Report any instances found unless Report verbosity is "Quiet".
if (installs && report_verbosity > 0) {
  if (installs == 1) {
    foreach dir (keys(installations)) {
      # empty - just need to set 'dir'.
    }
    if (ver == "unknown") {
      info = string("An unknown version of TWiki was detected on the remote host under\nthe path '", dir, "'.");
    }
    else {
      info = string("TWiki ", ver, " was detected on the remote host under\nthe path '", dir, "'.");
    }
  }
  else {
    info = string(
      "Multiple instances of TWiki were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under '", dir, "'\n");
    }
    info = chomp(info);
  }

  if (report_verbosity) {
    report = string(
      "\n",
      info, "\n"
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
