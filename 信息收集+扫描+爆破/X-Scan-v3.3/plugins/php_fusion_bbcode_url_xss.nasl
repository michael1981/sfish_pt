#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19597);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-2783");
  script_bugtraq_id(14688);
  script_xref(name:"OSVDB", value:"19072");

  script_name(english:"PHP-Fusion BBCode Nested URL Tag XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to cross-
site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the remote host is running a version
of PHP-Fusion that reportedly does not sufficiently sanitize input
passed in nested 'url' BBcode tags before using it in a post.  An
attacker may be able to exploit this flaw to cause arbitrary script
and HTML code to be executed in the context of a user's browser when
he/she views the malicious BBcode on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/409490" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP-Fusion 6.00.108 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for BBCode url tag script injection vulnerability in PHP-Fusion";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

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

  if (ver =~ "^([45][.,]|6[.,]00[.,](0|10[0-7]))") {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
