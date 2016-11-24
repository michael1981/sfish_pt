#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(18203);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2005-1597", "CVE-2005-1598");
  script_bugtraq_id(13529, 13532, 13534, 13375);
  script_xref(name:"OSVDB", value:"16297");
  script_xref(name:"OSVDB", value:"16298");

  script_name(english:"Invision Power Board < 2.0.4 Multiple Vulnerabilities (SQLi, XSS)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is vulnerable to
multiple attacks." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Invision Power Board on the
remote host suffers from multiple vulnerabilities :

  - SQL Injection Vulnerability
    The application fails to sanitize user-input supplied 
    through the 'pass_hash' cookie in the 'sources/login.php'
    script, which can be exploited to affect database
    queries, potentially revealing sensitive information.

  - Multiple Cross-Site Scripting Vulnerabilities
    An attacker can pass arbitrary HTML and script code 
    through the 'highlite' parameter of the 
    'sources/search.php' and 'sources/topics.php' scripts." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00073-05052005" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-05/0071.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-07/0257.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Invision Power Board 2.0.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in Invision Power Board < 2.0.4";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("invision_power_board_detect.nasl");
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
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^([01]\.|2\.0\.[0-3][^0-9]*)")
  {
   security_hole(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  }
}
