#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(22232);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2006-4211", "CVE-2006-4212");
  script_bugtraq_id(19552);
  script_xref(name:"OSVDB", value:"27964");
  script_xref(name:"OSVDB", value:"27965");

  script_name(english:"Owl Intranet Engine <= 0.91 Multiple Vulnerabilities");
  script_summary(english:"Checks for SQL injection flaw in Owl Intranet Engine");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
several issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Owl Intranet Engine, a web-based document
management system written in PHP. 

The version of Owl Intranet Engine on the remote host fails to
sanitize input to the session id cookie before using it in a database
query.  Provided PHP's 'magic_quotes_gpc' setting is disabled, an
unauthenticated attacker may be able to exploit this issue to uncover
sensitive information such as password hashes, modify data, launch
attacks against the underlying database, etc. 

In addition, the application reportedly suffers from at least one
cross-site scripting issue." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/forum/forum.php?forum_id=601910" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch referenced in the vendor advisory above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

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
if (thorough_tests) dirs = list_uniq(make_list("/owl", "/intranet", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  set_http_cookie(name: "owl_sessid", value: "'"+SCRIPT_NAME);
  # Try to exploit the flaw to generate a SQL syntax error.
  r = http_send_recv3(method: "GET", item:string(dir, "/index.php"), port:port);
  if (isnull(r)) exit(0);

  # There's a problem if we see an error message with our script name.
  if (string("sessions where sessid = ''", SCRIPT_NAME) >< r[2])
  {
    security_hole(port);

    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
