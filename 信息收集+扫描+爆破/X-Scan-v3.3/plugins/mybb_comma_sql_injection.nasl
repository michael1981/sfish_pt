#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(21053);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-0959");
  script_bugtraq_id(16631);
  script_xref(name:"OSVDB", value:"23554");

  script_name(english:"MyBB comma Cookie SQL Injection");
  script_summary(english:"Tries to generate a SQL syntax error");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to a SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote version of MyBB fails to sanitize input to the 'comma'
cookie used by several scripts before using it in database queries. 
This may allow an unauthenticated attacker to uncover sensitive
information such as password hashes, modify data, launch attacks
against the underlying database, etc. 

Note that successful exploitation requires that PHP's
'register_globals' setting be enabled." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/426653/30/30/threaded" );
 script_set_attribute(attribute:"solution", value:
"Disable PHP's 'register_globals' setting." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("mybb_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mybb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  # Try to exploit the flaw to generate a SQL syntax error.
  r = http_send_recv3(method: "GET", item:string(dir, "/showteam.php"), port:port, add_headers: make_array("Cookie", "comma='"+SCRIPT_NAME));
  if (isnull(r)) exit(0);

  # There's a problem if we see a syntax error with our script name.
  if (egrep(pattern:string("mySQL error: 1064.+near.+", SCRIPT_NAME, "'.+Query: SELECT u\\.\\*"), string: r[2])) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
