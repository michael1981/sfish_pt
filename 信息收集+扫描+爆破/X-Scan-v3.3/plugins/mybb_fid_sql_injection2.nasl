#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(19715);
  script_version ("$Revision: 1.11 $");

  script_cve_id("CVE-2005-2888");
  script_bugtraq_id(14762);
  script_xref(name:"OSVDB", value:"19234");
  script_xref(name:"OSVDB", value:"19235");

  script_name(english:"MyBB misc.php fid Parameter SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote version of MyBB is prone to a SQL injection attack due to
its failure to sanitize user-supplied input to the 'fid' parameter of
the 'misc.php' script before using it in database queries. 

In addition, the newreply.php script has been reported vulnerable
to SQL injection. However, Nessus has not tested for this." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/409743/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Enable PHP's 'magic_quotes_gpc' setting." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  summary["english"] = "Checks for fid parameter SQL injection vulnerability in MyBB (2)";
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

  # Try to exploit the flaws.
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/misc.php?",
      "action=rules&",
      "fid=-1'", SCRIPT_NAME
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # There's a problem if we see a syntax error with our script name.
  if (
    egrep(
      string:res,
      pattern:string("mySQL error: 1064<br>.+near '", SCRIPT_NAME, "' .+Query: SELECT \\* FROM .*forums")
    )
  ) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
