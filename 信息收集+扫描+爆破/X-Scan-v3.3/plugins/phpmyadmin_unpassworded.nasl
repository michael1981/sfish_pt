#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40352);
  script_version("$Revision: 1.3 $");

  script_name(english:"phpMyAdmin Installation Not Password Protected");
  script_summary(english:"Checks if PMA requires login");

  script_set_attribute(
    attribute:"synopsis",
    value:"Access to the remote PHP application is not password protected."
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of phpMyAdmin installed on the remote web server allows\n",
      "unrestricted, unauthenticated access.  This is likely due to setting\n",
      "the 'auth_type' to 'config' and storing login credentials in the\n",
      "configuration file.\n\n",
      "A remote attacker could exploit this to execute arbitrary SQL queries,\n",
      "delete databases, or possibly even execute arbitrary code remotely."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/documentation/#authentication_modes"
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Restrict access to phpMyAdmin using one of the methods referred to in\n",
      "the vendor's documentation."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/07/23"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server does not support PHP scripts.");

install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0, "phpMyAdmin wasn't detected on port " + port);
matches = eregmatch(string:install, pattern:"^.+ under (/.*)$");
if (isnull(matches)) exit(1, "Error reading phpMyAdmin dir from the KB");

dir = matches[1];
if (dir != '/') url = string(dir, '/');
else url = dir;

res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The web server didn't respond to the GET request.");

# If this doesn't look like a login page, and it looks like it has some
# JS variables related to the PMA interface, it's probably unpassworded
if (
  'Log in' >!< res[2] &&
  '<input type="text" name="pma_username"' >!< res[2] &&
  ( 'var server' >< res[2] && 'var table' >< res[2] && 'var db' >< res[2] ||
  # older versions: phpmyadmin 2.6.3, for example
    '<p>phpMyAdmin is more friendly with a <b>frames-capable</b> browser.</p>' >< res[2] )
)
{
  report = "";
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "  URL : ", build_url(qs:url, port:port), "\n"
    );
  }

  # Checkif phpmyadmin is broken or not
  if ( "<!-- PMA-SQL-ERROR -->" >< res[2] && 
       "Cannot connect: invalid settings" >< res[2] &&
       "server rejected the connection" >< res[2] )
     report = strcat(report, 
'\nIt appears that phpmyadmin is not configured properly and cannot 
communicate with the database, so this weakness might not be exploited 
now.'); 

  if (strlen(report) > 0)
    security_hole(port:port, extra:report);
  else
    security_hole(port:port);
}
else exit(0, "phpMyAdmin appears to restrict access with a login page.");
