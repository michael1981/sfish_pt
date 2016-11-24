#
# (C) Tenable Network Security
#



include("compat.inc");

if (description) {
  script_id(18612);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-2153", "CVE-2005-2154");
  script_bugtraq_id(14127);
  script_xref(name:"OSVDB", value:"17714");
  script_xref(name:"OSVDB", value:"17715");
  script_xref(name:"OSVDB", value:"17716");
  script_xref(name:"OSVDB", value:"17717");

  name["english"] = "osTicket <= 1.3.1 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of osTicket installed on the remote host suffers from
several vulnerabilities, including:

  - A Local File Include Vulnerability
    The application fails to sanitize user-supplied input
    to the 'inc' parameter in the 'view.php' script. An 
    attacker may be able to exploit this flaw to run 
    arbitrary PHP code found in files on the remote host 
    provided PHP's 'register_globals' setting is enabled.

  - A SQL Injection Vulnerability
    An authenticated attacker can affect SQL queries via
    POST queries due to a failure of the application to
    filter input to the 'ticket' variable in the 
    'class.ticket.php' code library." );
 script_set_attribute(attribute:"see_also", value:"http://www.osticket.com/forums/showthread.php?t=1283" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/403990/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.osticket.com/news/sec,05,01.html" );
 script_set_attribute(attribute:"solution", value:
"Apply the security update for version 1.3.1." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  summary["english"] = "Checks version of osTicket";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("osticket_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");


# nb: the vendor has issued a patch that doesn't change the version.
if (report_paranoia < 2) exit(0);


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/osticket"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # Check the version number -- both flaws require authentication.
  if (ver && ver  =~ "^(0\.|1\.([01]\.|2\.[0-7]|3\.[01]))") {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
