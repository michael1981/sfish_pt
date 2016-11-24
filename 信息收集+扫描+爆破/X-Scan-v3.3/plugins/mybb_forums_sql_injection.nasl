#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(21052);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2006-1065");
  script_xref(name:"OSVDB", value:"23784");

  script_name(english:"MyBB search.php forums Parameter SQL Injection");
  script_summary(english:"Checks for forums parameter SQL injection vulnerability in MyBB");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote version of MyBB fails to sanitize input to the 'forums'
parameter of the 'search.php' script before using it in database
queries.  This may allow an unauthenticated attacker to uncover
sensitive information such as password hashes, modify data, launch
attacks against the underlying database, etc." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/426631/30/30/threaded" );
 script_set_attribute(attribute:"solution", value:
"Edit 'search.php' and ensure 'forum' takes on only integer values as
described in the original advisory." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );
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

  # First we need a username.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  pat = '<a href="member.php\\?action=profile&amp;uid=[^>]+>([^<]+)</a>';
  matches = egrep(pattern:pat, string:res);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      user = eregmatch(pattern:pat, string:match);
      if (!isnull(user)) {
        user = user[1];
        break;
      }
    }
  }

  # If we have a username...
  if (user) {
    # Try to exploit the flaw to generate a SQL syntax error.
    w = http_send_recv3(method:"GET", 
      item:string(
        dir, "/search.php?",
        "action=do_search&",
        "postthread=1&",
        "author=", user, "&",
        "matchusername=1&",
        "forums[]=-1'", SCRIPT_NAME
      ), 
      port:port
    );
    if (isnull(w)) exit(1, "the web server did not answer");
    res = w[2];

    # There's a problem if we see a syntax error with our script name.
    if (egrep(pattern:string("mySQL error: 1064.+near '", SCRIPT_NAME, ",'.+Query: SELECT f\\.fid"), string:res)) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
  else {
    debug_print("couldn't find a username to use!", level:1);
  }
}
