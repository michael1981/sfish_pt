#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(18569);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-2045");
  script_bugtraq_id(14029);
  script_xref(name:"OSVDB", value:"17597");
  script_xref(name:"OSVDB", value:"17598");
  script_xref(name:"OSVDB", value:"17599");

  script_name(english:"DUportal Pro Multiple Scripts SQL Injection (2)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is vulnerable
to multiple SQL injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running DUportal Pro, an ASP-based product suite
from DUware for building web portals / online communities. 

The installed version of DUportal Pro fails to properly sanitize user-
supplied input in several instances before using it in SQL queries. 
By exploiting these flaws, an attacker can affect database queries,
possibly disclosing sensitive data and launching attacks against the
underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://echo.or.id/adv/adv19-theday-2005.txt" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-06/0172.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple SQL injection vulnerabilities in DUportal Pro";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_asp(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit one of the flaws.
  u = string(
      dir, "/Articles/default.asp?",
      "iChannel=", SCRIPT_NAME, "'&",
      "nChannel=Articles"
    );
  r = http_send_recv3(method: "GET", port:port, item: u);
  if (isnull(r)) exit(0);

  # There's a problem if...
  if (
    # it looks like DUportal Pro and...
    'href="../assets_blue/DUportalPro.css" rel="stylesheet"' >< r[2] && 
    # there's a syntax error.
    string("Syntax error in string in query expression 'CHA_ID = ", SCRIPT_NAME, "'") >< r[2]
  ) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
