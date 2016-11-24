#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(18567);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-2048");
  script_bugtraq_id(14035);
  script_xref(name:"OSVDB", value:"17584");
  script_xref(name:"OSVDB", value:"17585");
  script_xref(name:"OSVDB", value:"17586");
  script_xref(name:"OSVDB", value:"17587");

  script_name(english:"DUforum Multiple Scripts SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is vulnerable
to multiple SQL injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running DUforum, a web-based message board written
in ASP from DUware. 

The installed version of DUforum fails to properly sanitize user-
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

 
  summary["english"] = "Checks for multiple SQL injection vulnerabilities in DUforum";
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
      dir, "/forums.asp?",
      "iFor=", SCRIPT_NAME, "'"
    );
  r = http_send_recv3(port:port, method: "GET", item: u);
  if (isnull(r)) exit(0);

  # There's a problem if...
  if (
    # it looks like DUforum and...
    'href="assets/DUforum.css" rel="stylesheet"' >< r[2] && 
    # there's a syntax error.
    string("Syntax error in string in query expression 'FOR_ID = ", SCRIPT_NAME, "'") >< r[2]
  ) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
