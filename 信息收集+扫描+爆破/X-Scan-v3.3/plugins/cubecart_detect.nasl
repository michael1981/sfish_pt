#
# (C) Tenable Network Security
#



include("compat.inc");

if (description) {
  script_id(17998);
  script_version("$Revision: 1.6 $");

  name["english"] = "CubeCart Detection";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a shopping cart package written in PHP." );
 script_set_attribute(attribute:"description", value:
"The remote host is running CubeCart, a shopping cart package using PHP
and MySQL." );
 script_set_attribute(attribute:"see_also", value:"http://www.cubecart.com/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
script_end_attributes();

 
  summary["english"] = "Checks for the presence of CubeCart";
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


# Search for CubeCart.
installs = 0;

# '/store' is the web dir name suggested by the cubecart installation guide
if (thorough_tests) dirs = list_uniq(make_list('/store', cgi_dirs()));
else dirs = cgi_dirs();

foreach dir (dirs) {
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If it's CubeCart.
  if (egrep(string:res, pattern:"Powered by .+CubeCart</a>")) {
    if (dir == "") dir = "/";

    # Try to identify the version number from the page itself.
    pat = "Powered by .+CubeCart</a> ([^<]+)(<br| &copy;)";
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        ver = ver[1];
        break;
      }
    }

    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    set_kb_item(
      name:string("www/", port, "/cubecart"),
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
      info = string("An unknown version of CubeCart was detected on the remote\nhost under the path ", dir, ".");
    }
    else {
      info = string("CubeCart ", ver, " was detected on the remote host under\nthe path ", dir, ".");
    }
  }
  else {
    info = string(
      "Multiple instances of CubeCart were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  security_note(port:port, extra: info);
}
