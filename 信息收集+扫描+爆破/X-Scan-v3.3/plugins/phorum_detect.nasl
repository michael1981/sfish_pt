#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(17349);
  script_version("$Revision: 1.6 $");

  name["english"] = "Phorum Detection";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a bulletin board system written in PHP." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Phorum, a web-based message board written
in PHP." );
 script_set_attribute(attribute:"see_also", value:"http://phorum.org/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );


script_end_attributes();

 
  summary["english"] = "Checks for presence of Phorum";
  script_summary(english:summary["english"]);
 
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


# Search for Phorum.
installs = 0;
foreach dir (cgi_dirs()) {
  # nb: while the version number isn't always found in 'index.php',
  #     it does seem to be in 'admin.php'.
  r = http_send_recv3(method:"GET", item:string(dir, "/admin.php"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it's Phorum.
  if ("title>Phorum Admin<" >< res) {
    if (dir == "") dir = "/";

    # Try to identify the version number from the page itself.
    pat = "Phorum Admin.+version ([^<]+)<";
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    ver = NULL;
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
    # If unsuccessful, try to grab it from the changelog.
    if (isnull(ver)) {
      r = http_send_recv3(method:"GET", item:dir + "/docs/CHANGES", port:port);
      if (isnull(r)) exit(1, "the web server did not answer");
      res = r[1];

      pat = "^Release: phorum\.(.+)";
      matches = egrep(pattern:pat, string:res, icase:TRUE);
      if (matches) {
        foreach match (split(matches)) {
          match = chomp(match);
          ver = eregmatch(pattern:pat, string:match, icase:TRUE);
          if (!isnull(ver)) {
            ver = ver[1];
            break;
          }
        }
      }
    }
    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    set_kb_item(
      name:string("www/", port, "/phorum"),
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
      info = string("An unknown version of Phorum was detected on the remote\nhost under the path ", dir, ".");
    }
    else {
      info = string("Phorum ", ver, " was detected on the remote host under\nthe path ", dir, ".");
    }
  }
  else {
    info = string(
      "Multiple instances of Phorum were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  security_note(port:port, extra: info);
}
