#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(17259);
  script_version("$Revision: 1.8 $");

  script_bugtraq_id(11545);

  script_name(english:"phpList <= 2.6.3 Multiple Vulnerabilities");
  script_summary(english:"Checks version of phpList");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of phpList installed on the
remote host is prone to arbitrary command execution as well as
information disclosure vulnerabilities." );
 script_set_attribute(attribute:"see_also", value:"http://tincan.co.uk/?lid=851" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpList 2.6.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("phplist_detect.nasl");
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
install = get_kb_item(string("www/", port, "/phplist"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # Versions 2.6.3 and older are vulnerable.
  if (ver =~ "^([01]\..*|2\.([0-5]\..*|6\.[0-3]))") {
    security_hole(port);
    exit(0);
  }
}
