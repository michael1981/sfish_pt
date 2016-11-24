#
# (C) Tenable Network Security
#

include("compat.inc");

if (description)
{
  script_id(22055);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-3775");
  script_bugtraq_id(18997);
  script_xref(name:"OSVDB", value:"27335");

  script_name(english:"MyBB HTTP Header CLIENT-IP Field SQL Injection");
  script_summary(english:"Checks for CLIENT-IP SQL injection vulnerability in MyBB");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to a SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote version of MyBB fails to sanitize input to the 'CLIENT-IP'
request header before using it in a database query when initiating a
sesion in 'inc/class_session.php'.  This may allow an unauthenticated
attacker to uncover sensitive information such as password hashes,
modify data, launch attacks against the underlying database, etc. 

Note that successful exploitation is possible regardless of PHP's
settings." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/mybb_115_sql.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/440163/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://community.mybboard.net/showthread.php?tid=10555" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/3653" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
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
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mybb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the flaw to generate a SQL syntax error.
  magic = string("'", SCRIPT_NAME, "--");

  w = http_send_recv3(method:"GET", item:string(dir, "/"), port:port,
    add_headers: make_array("CLIENT-IP", magic));
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # There's a problem if we see a syntax error with our script name.
  if (
    "SQL error: 1064" >< res &&
    string("near ", magic, "'' at line") >< res &&
    (
      "SELECT sid,uid" >< res ||
      "WHERE ip='" >< res
    )
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
