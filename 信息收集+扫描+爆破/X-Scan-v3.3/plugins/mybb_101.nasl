#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(20373);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2005-4602");
  script_bugtraq_id(16082, 16097);
  script_xref(name:"OSVDB", value:"22159");

  script_name(english:"MyBB < 1.01 SQL Injection");
  script_summary(english:"Checks for SQL injection vulnerabilities in MyBB < 1.01");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server has a PHP application that is affected by
multiple SQL injection vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of MyBB fails to validate user input to the
'mybbadmin' cookie in the 'admin/global.php' script as well as the
extension of a file upload before using them in database queries.  An
attacker may be able to leverage these issues to disclose sensitive
information, modify data, or launch attacks against the underlying
database. 

Note that exploitation of the second issue may require authentication
while the first does not." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/420573" );
 script_set_attribute(attribute:"see_also", value:"http://community.mybboard.net/showthread.php?tid=5633" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MyBB version 1.01 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

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

  # Try to exploit flaw in the cookie to generate a syntax error.
  magic = rand_str(length:8);
  r = http_send_recv3(method: "GET", port:port,
 item:string(dir, "/admin/global.php?action=", SCRIPT_NAME), 
 add_headers: make_array("Cookie", "mybbadmin='"+magic)
  );
  if (isnull(r)) exit(0);

  # There's a problem if we get a syntax error involving the word "nessus".
  #
  # nb: the code splits the cookie on "_" so we can't just use our script 
  #     name as we usually do.
  if (egrep(pattern:"an error in your SQL syntax.+ WHERE uid=''" + magic, string: r[2])) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
