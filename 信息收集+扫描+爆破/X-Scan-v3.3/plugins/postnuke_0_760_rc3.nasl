#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18360);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2005-1621", "CVE-2005-1697", "CVE-2005-1698", "CVE-2005-1699", "CVE-2005-1700");
  script_bugtraq_id(13706, 13789);
  script_xref(name:"OSVDB", value:"16617");
  script_xref(name:"OSVDB", value:"16782");
  script_xref(name:"OSVDB", value:"16785");
  script_xref(name:"OSVDB", value:"16786");
  script_xref(name:"OSVDB", value:"16792");
  script_xref(name:"OSVDB", value:"16793");
  script_xref(name:"OSVDB", value:"16794");
  script_xref(name:"OSVDB", value:"16795");
  script_xref(name:"OSVDB", value:"16799");
  script_xref(name:"OSVDB", value:"20687");
  script_xref(name:"OSVDB", value:"20688");
  script_xref(name:"OSVDB", value:"20689");
  script_xref(name:"OSVDB", value:"20690");
  script_xref(name:"OSVDB", value:"20691");
  script_xref(name:"OSVDB", value:"20692");

  script_name(english:"PostNuke <= 0.760 RC4a Multiple Vulnerabilities");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to several
attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PostNuke version 0.760 RC4a or older. 
These versions suffer from several vulnerabilities, among them :

  - Multiple Remote Code Injection Vulnerabilities
    An attacker can read arbitrary files on the remote and 
    possibly inject arbitrary PHP code remotely.

  - SQL Injection Vulnerabilities
    Weaknesses in the 'Xanthia' and 'Messages' modules allow 
    attackers to affect database queries, possibly resulting
    in the disclosure of sensitive information such as user
    passwords and even execution of arbitrary PHP code on
    the remote host.

  - Multiple Cross-Site Scripting Vulnerabilities
    An attacker can inject arbitrary script code into the
    browser of users leading to disclosure of session 
    cookies, redirection to other sites, etc.

  - Multiple Path Disclosure Vulnerabilities
    An attacker can discover details about the underlying
    installation directory structure by calling various
    include scripts directly." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-05/0197.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-05/0254.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-05/0255.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-05/0256.html" );
 script_set_attribute(attribute:"see_also", value:"http://community.postnuke.com/Article2691.htm" );
 script_set_attribute(attribute:"solution", value:
"Apply the security fix package referenced in the article above to
upgrade to PostNuke version 0.750.0b." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_summary(english:"Detects multiple vulnerabilities in PostNuke <= 0.760 RC4a");

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("postnuke_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/postnuke"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  test_cgi_xss(port: port, cgi: "/index.php", 
 pass_re: "root:.+:0:", high_risk: 1, sql_injection: 1, 
 qs: string(
        "module=Blocks&",
        "type=lang&",
        "func=../../../../../../../../../../../../etc/passwd%00"
      )
  );
}
