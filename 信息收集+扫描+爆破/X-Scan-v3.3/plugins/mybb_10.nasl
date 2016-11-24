#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(20342);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-4199", "CVE-2005-4200");
  script_bugtraq_id(15793);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"21600");
    script_xref(name:"OSVDB", value:"21601");
  }

  script_name(english:"MyBB < 1.0 Multiple SQL Injection Vulnerabilities");
  script_summary(english:"Checks for multiple SQL injection vulnerabilities in MyBB < 1.0");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server has a PHP application that is affected by
multiple SQL injection vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of MyBB fails to validate user input to several
parameters of the 'calendar.php', 'usercp.php', 'member.php', and
'showthread.php' scripts before using them in database queries.  An
attacker leverage this issues to manipulate those queries, which may
lead to disclosure of sensitive information, modification of data, or
attacks against the underlying database. 

Note that these flaws can be exploited even if PHP's
'register_globals' setting is disabled and its 'magic_quotes_gpc'
setting is enabled.  Also, some do not require that an attacker first
authenticate." );
 script_set_attribute(attribute:"see_also", value:"http://www.trapkit.de/advisories/TKADV2005-12-001.txt" );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2005-December/040584.html" );
 script_set_attribute(attribute:"see_also", value:"http://community.mybboard.net/showthread.php?tid=5184" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MyBB 1.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
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

  # Make sure one of the affected scripts exists.
  w = http_send_recv3(method:"GET",item:string(dir, "/calendar.php"), port:port);
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # If it does...
  if ('<form action="calendar.php" method=' >< res) {
    postdata = string(
      "month=11'", SCRIPT_NAME, "&",
      "day=11&",
      "year=2005&",
      "subject=NESSUS&",
      "description=Plugin+Check&",
      "action=do_addevent"
    );
    w = http_send_recv3(method: "POST ", item: dir+"/calendar.php", port: port,
      content_type: "application/x-www-form-urlencoded",
      data: postdata);
    if (isnull(w)) exit(1, "the web server did not answer");
    res = strcat(w[0], w[1], '\r\n', w[2]);

    # There's a problem if we get a syntax error involving our script name.
    if (egrep(pattern:string("an error in your SQL syntax.+ near '", SCRIPT_NAME), string:res)) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
