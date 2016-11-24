#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(19716);
  script_version ("$Revision: 1.12 $");
  script_cve_id("CVE-2005-4200");
  script_bugtraq_id(14786);
  script_xref(name:"OSVDB", value:"22158");
  script_xref(name:"OSVDB", value:"22157");

  script_name(english:"MyBB ratethread.php rating Parameter SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote version of MyBB is prone to a SQL injection attack due to
its failure to sanitize user-supplied input to the 'rating' parameter
of the 'ratethread.php' script before using it in database queries. 

In addition, the 'member.php' script has been reported vulnerable to 
SQL injection in the 'rating' parameter. However, Nessus has not
tested for this." );
 script_set_attribute(attribute:"see_also", value:"http://www.s4a.cc/forum/archive/index.php/t-3953.html" );
 script_set_attribute(attribute:"solution", value:
"Enable PHP's 'magic_quotes_gpc' setting." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  summary["english"] = "Checks for rating parameter SQL injection vulnerability in MyBB";
  script_summary(english:summary["english"]);

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

  # First we need a thread id.
  w = http_send_recv3(method:"GET", item:string(dir, "/index.php"), port:port);
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  pat = '<a href="showthread\\.php\\?tid=([0-9]+)&amp;action=lastpost';
  matches = egrep(pattern:pat, string:res);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      thread = eregmatch(pattern:pat, string:match);
      if (!isnull(thread)) {
        tid = thread[1];
        break;
      }
    }
  }

  # If we have a thread id.
  if (isnull(tid)) {
    debug_print("couldn't find a thread id to use!", level:1);
  }
  else {
    # Try to exploit the flaw.
    #
    # nb: the advisory uses a POST but the code allows for a GET,
    #     and that's quicker in a plugin.
    w = http_send_recv3(method:"GET",
      item:string(
        dir, "/ratethread.php?",
        "tid=", tid, "&",
        "rating=1'", SCRIPT_NAME
      ), 
      port:port
    );
    if (isnull(w)) exit(1, "the web server did not answer");
    res = w[2];

    # There's a problem if we see a syntax error with our script name.
    if (
      egrep(
        string:res,
        pattern:string("mySQL error: 1064<br>.+near '", SCRIPT_NAME, "' .+Query: UPDATE .*threads SET numratings")
      )
    ) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
