#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19519);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-2869");
  script_bugtraq_id(14674, 14675);
  script_xref(name:"OSVDB", value:"19048");
  script_xref(name:"OSVDB", value:"19049");

  script_name(english:"phpMyAdmin < 2.6.4 Multiple XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
cross-site scripting vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of phpMyAdmin installed on the
remote host may suffer from two cross-site scripting vulnerabilities
due to its failure to sanitize user input to the 'error' parameter of
the 'error.php' script and in 'libraries/auth/cookie.auth.lib.php'.  A
remote attacker may use these vulnerabilities to cause arbitrary HTML
and script code to be executed in a user's browser within the context
of the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/tracker/index.php?func=detail&aid=1240880&group_id=23067&atid=377408" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/tracker/index.php?func=detail&aid=1265740&group_id=23067&atid=377408" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin 2.6.4-rc1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple cross-site scripting vulnerabilities in phpMyAdmin < 2.6.4";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");
 
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencie("phpMyAdmin_detect.nasl");
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
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^([01]\.|2\.([0-5]\.|6\.[0-3]))")
  {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}

