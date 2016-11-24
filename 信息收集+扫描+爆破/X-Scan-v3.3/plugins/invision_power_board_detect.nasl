#
# (C) Tenable Network Security
#



include("compat.inc");

if (description) {
  script_id(17203);
  script_version("$Revision: 1.6 $");
 
  script_name(english:"Invision Power Board Software Detection");
  script_summary(english:"Checks for the presence of Invision Power Board");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a content management system written in
PHP." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Invision Power Board , a suite of PHP
scripts for operating a web-based bulletin board system." );
 script_set_attribute(attribute:"see_also", value:"http://www.invisionboard.com/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
script_end_attributes();

 
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/ipb", "/invision", "/forums", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  req = http_get(item:string(dir, "/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) exit(0);

  # Sample banners:
  #   v1.1.2 &copy; 2003 &nbsp;<a href='http://www.invisionpower.com' target='_blank'>IPS, Inc.</a>
  #   v1.2 &copy; 2003 &nbsp;<a href='http://www.invisionpower.com' target='_blank'>IPS, Inc.</a>
  #   v1.3 Final &copy; 2003 &nbsp;<a href='http://www.invisionpower.com' target='_blank'>IPS, Inc.</a>
  #   v1.3.1 Final &copy; 2003 &nbsp;<a href='http://www.invisionpower.com' target='_blank'>IPS, Inc.</a>
  #   v2.0.0 PF 4 &copy; 2005 &nbsp;<a href='http://www.invisionpower.com' target='_blank'>IPS, Inc.</a>
  #   v2.0.3  &copy; 2005 &nbsp;IPS, Inc.
  pat = "v(.+) &copy; (19|20)[0-9][0-9] .+IPS, Inc\.";
  matches = egrep(pattern:pat, string:res);
  foreach match (split(matches)) {
    match = chomp(match);
    ver = eregmatch(pattern:pat, string:match);
    if (ver == NULL) break;
    ver = chomp(ver[1]);

    # Success!
    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/invision_power_board"), 
      value:string(ver, " under ", dir)
    );
    installations[dir] = ver;
    ++installs;

    # nb: only worried about the first match.
    break;
  }
  # Scan for multiple installations only if "Thorough Tests" is checked.
  if (installs && !thorough_tests) break;
}

# Report any instances found unless Report verbosity is "Quiet".
if (installs && report_verbosity > 0) {
  if (installs == 1) {
    foreach dir (keys(installations)) {
      # empty - just need to set 'dir'.
    }
    info = string("Invision Power Board ", ver, " was detected on the remote host under\nthe path ", dir, ".");
  }
  else {
    info = string(
      "Multiple instances of Invision Power Board were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  report = '\n' + info;
  security_note(port:port, extra:report);
}
