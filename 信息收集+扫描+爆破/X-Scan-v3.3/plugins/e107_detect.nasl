#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20129);
  script_version("$Revision: 1.6 $");

  script_name(english:"e107 Detection");
  script_summary(english:"Checks for the presence of e107");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a content management system (CMS)
written in PHP." );
 script_set_attribute(attribute:"description", value:
"The remote host is running e107, a content management system written
in PHP and with a MySQL back-end." );
 script_set_attribute(attribute:"see_also", value:"http://e107.org/news.php" );
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

port = get_http_port(default:80, embedded:0);
if (!can_host_php(port:port)) exit(0);


# Search for e107.
if (thorough_tests) dirs = list_uniq(make_list("/e107", "/cms", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  # Try to grab e107's main admin page.
  r = http_send_recv3(method:"GET",item:string(dir, "/e107_admin/admin.php"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it looks like the right page...
  if (egrep(pattern:"<input [^>]*name='auth(name|pass)'", string:res)) {

    # It doesn't seem possible to identify the version so just 
    # mark it as "unknown".
    #if (isnull(ver)) ver = "unknown";
    ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/e107"),
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
      info = string("An unknown version of e107 was detected on the remote\nhost under the path ", dir, ".");
    }
    else {
      info = string("e107 ", ver, " was detected on the remote host under\nthe path ", dir, ".");
    }
  }
  else {
    info = string(
      "Multiple instances of e107 were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  security_note(port:port, extra:'\n'+info);
}
