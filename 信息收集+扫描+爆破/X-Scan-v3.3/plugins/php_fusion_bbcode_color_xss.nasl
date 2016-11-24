#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19311);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2005-2401", "CVE-2005-3159");
  script_bugtraq_id(14332, 14489);
  script_xref(name:"OSVDB", value:"18111");
  script_xref(name:"OSVDB", value:"18708");

  script_name(english:"PHP-Fusion <= 6.00.106 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains several PHP scripts that suffer from SQL
injection and cross-site scripting flaws." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
PHP-Fusion that suffers from multiple vulnerabilities :

  - SQL Injection Vulnerability
    The application fails to sanitize user-supplied input to the 
    'msg_view' parameter of the 'messages.php' script before 
    using it in database queries. Exploitation requires that an 
    attacker first authenticate and that PHP's 'magic_quotes_gpc'
    be disabled.

  - HTML Injection Vulnerability
    An attacker can inject malicious CSS (Cascading Style Sheets)
    codes through [color] tags, thereby affecting how the site is 
    rendered whenever users view specially-crafted posts." );
 script_set_attribute(attribute:"see_also", value:"http://www.php-fusion.co.uk/news.php?readmore=244" );
 script_set_attribute(attribute:"see_also", value:"http://www.php-fusion.co.uk/news.php?readmore=247" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP-Fusion 6.00.107 or later or apply the patches in the
vendor's advisories referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in PHP-Fusion <= 6.00.106";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("php_fusion_detect.nasl");
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
install = get_kb_item(string("www/", port, "/php-fusion"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^([45][.,]|6[.,]00[.,](0|10\[0-6]))") {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
