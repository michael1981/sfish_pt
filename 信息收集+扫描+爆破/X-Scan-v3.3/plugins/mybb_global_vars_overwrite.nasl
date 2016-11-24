#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(21239);
  script_version("$Revision: 1.6 $");

  script_bugtraq_id(17564);
  script_xref(name:"OSVDB", value:"24710");
  script_cve_id("CVE-2006-1912");

  script_name(english:"MyBB global.php Global Variable Overwrite");
  script_summary(english:"Checks for globals.php SQL injection vulnerability in MyBB");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
global variable overwrite vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote version of MyBB does not properly initialize global
variables in the 'global.php' and 'inc/init.php' scripts.  An
unauthenticated attacker can leverage this issue to overwrite global
variables through GET and POST requests and launch other attacks
against the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/431061/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://community.mybboard.net/showthread.php?tid=8232" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MyBB 1.1.1 or later." );
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


# Test an install.
install = get_kb_item(string("www/", port, "/mybb"));

if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw to generate a SQL syntax error.
  w = http_send_recv3(method:"GET", 
    item:string(
      dir, "/global.php?",
      "_SERVER[HTTP_CLIENT_IP]='", SCRIPT_NAME
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # There's a problem if we see a syntax error with our script name.
  if (egrep(pattern:string("mySQL error: 1064.+near '", SCRIPT_NAME, "''.+Query: SELECT sid,uid"), string:res)) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
