#
# (C) Tenable Network Security, Inc.
# 



include("compat.inc");

if (description) {
  script_id(18691);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-2247");
  script_bugtraq_id(14224);
  script_xref(name:"OSVDB", value:"17834");

  name["english"] = "Moodle < 1.5.1 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple problems." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Moodle installed on the remote
host suffers from several, as-yet unspecified, flaws." );
 script_set_attribute(attribute:"see_also", value:"http://moodle.org/doc/index.php?file=release.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Moodle 1.5.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in Moodle < 1.5.1";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("moodle_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/moodle"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^1\.([0-4].*|5([^0-9]|$))") security_hole(port);
}
