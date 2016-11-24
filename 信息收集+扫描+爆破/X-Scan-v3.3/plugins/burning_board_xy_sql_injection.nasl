#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19524);
  script_version ("$Revision: 1.10 $");

  script_cve_id("CVE-2005-2673");
  script_bugtraq_id(14617);
  script_xref(name:"OSVDB", value:"19035");

  script_name(english:"Woltlab Burning Board modcp.php Multiple Parameter SQL Injection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote version of Burning Board / Burning Board Lite is prone to
SQL injection attacks due to its failure to sanitize user-supplied
input to the 'x' and 'y' parameters of the 'modcp.php' script before
using it in database queries.  Provided an attacker has moderator
privileges, these flaws may allow him to uncover sensitive information
(such as password hashes), modify existing data, and launch attacks
against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/408660" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P" );
script_end_attributes();

 
  script_summary(english:"Checks for SQL injection vulnerabilities in Burning Board modcp.php script");
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("burning_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# Test any installs.
wbb = get_kb_list(string("www/", port, "/burning_board"));
wbblite = get_kb_list(string("www/", port, "/burning_board_lite"));
if (isnull(wbb)) {
  if (isnull(wbblite)) exit(0);
  else installs = make_list(wbblite);
}
else if (isnull(wbblite)) {
  if (isnull(wbb)) exit(0);
  else installs = make_list(wbb);
}
else {
  kb1 = get_kb_list(string("www/", port, "/burning_board"));
  kb2 = get_kb_list(string("www/", port, "/burning_board_lite"));
  if ( isnull(kb1) ) kb1 = make_list();
  else kb1 = make_list(kb1);
  if ( isnull(kb2) ) kb1 = make_list();
  else kb2 = make_list(kb2);
  installs = make_list( kb1, kb2 );
}
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];

    if (ver =~ "^2\.([0-2]|3\.[0-3])") {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
