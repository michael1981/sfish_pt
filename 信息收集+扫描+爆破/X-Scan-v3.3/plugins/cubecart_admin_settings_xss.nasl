#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(17260);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-0606", "CVE-2005-0607");
  script_bugtraq_id(12658);
  script_xref(name:"OSVDB", value:"13810");
  script_xref(name:"OSVDB", value:"14213");
  script_xref(name:"OSVDB", value:"14214");
  script_xref(name:"OSVDB", value:"14215");
  script_xref(name:"OSVDB", value:"14216");
  script_xref(name:"OSVDB", value:"14217");
  script_xref(name:"OSVDB", value:"14218");
  script_xref(name:"OSVDB", value:"14219");
  script_xref(name:"OSVDB", value:"14220");
  script_xref(name:"OSVDB", value:"14221");

  script_name(english:"CubeCart < 2.0.6 settings.inc.php Multiple Script XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of CubeCart installed on the
remote host suffers from multiple cross-site scripting and path
disclosure vulnerabilities due to a failure to sanitize user input in
'admin/settings.inc.php', which is used by various scripts." );
 script_set_attribute(attribute:"see_also", value:"http://lostmon.blogspot.com/2005/02/cubecart-20x-multiple-variable-xss.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.cubecart.com/site/forums/index.php?showtopic=6032" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CubeCart 2.0.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
  script_summary(english:"Checks version of CubeCart");
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("cubecart_detect.nasl");
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
install = get_kb_item(string("www/", port, "/cubecart"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # If it's CubeCart 2.0.0 - 2.0.5, there's a problem.
  if (ver =~ "^2\.0\.[0-5]")
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
