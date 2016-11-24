#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(17689);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2005-0992");
  script_bugtraq_id(12982);
  script_xref(name:"OSVDB", value:"15226");

  script_name(english:"phpMyAdmin index.php convcharset Parameter XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The installed version of phpMyAdmin suffers from a cross-site
scripting vulnerability due to its failure to sanitize user input to
the 'convcharset' parameter of the 'index.php' script.  A remote
attacker may use these vulnerabilities to cause arbitrary code to be
executed in a user's browser to steal authentication cookies and the
like." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin 2.6.2-rc1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  script_summary(english:"Checks for convcharset cross-site scripting vulnerability in phpMyAdmin");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("cross_site_scripting.nasl", "phpMyAdmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);

# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "');</script>";

# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  # Try to exploit the vulnerability with our XSS.
  test_cgi_xss(port: port, cgi: "/index.php", dirs: make_list(dir),
 pass_str: xss, qs: string(
      "pma_username=&",
      "pma_password=&",
      "server=1&",
      "lang=en-iso-8859-1&",
      "convcharset=%5C%22%3E", urlencode(str:xss)
    ));
}
