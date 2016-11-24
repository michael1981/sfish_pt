#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19232);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-2074", "CVE-2005-2075");
  script_bugtraq_id(14066);
  script_xref(name:"OSVDB", value:"17610");
  script_xref(name:"OSVDB", value:"17611");

  name["english"] = "PHP-Fusion <= 6.00.105 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that contains two
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
PHP-Fusion that is affected by two vulnerabilities :

  - An Information Disclosure Vulnerability
    PHP Fusion stores database backups in a known location 
    within the web server's documents directory. An attacker
    may be able to retrieve these backups and obtain 
    password hashes or other sensitive information from the
    database.

  - Multiple Cross-Site Scripting Vulnerabilities
    An attacker can inject malicious HTML and script code 
    into the 'news_body', 'article_description', and the 
    'article_body' parameters when submitting news or an
    article." );
 script_set_attribute(attribute:"see_also", value:"http://dark-assassins.com/forum/viewtopic.php?t=142" );
 script_set_attribute(attribute:"see_also", value:"http://dark-assassins.com/forum/viewtopic.php?t=145" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP-Fusion 6.00.106 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
 script_end_attributes();
 
  summary["english"] = "Checks for multiple vulnerabilities in PHP-Fusion <= 6.00.105";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english: "CGI abuses");

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

  # nb: 6.00.105 is known to be affected; other versions may also be.
  if (ver =~ "^([0-5][.,]|6[.,]00[.,](0|10[0-5]))")
  {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  }
}
