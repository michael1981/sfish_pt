#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20068);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-3056");
  script_bugtraq_id(14960);
  script_xref(name:"OSVDB", value:"19716");

  script_name(english:"TWiki %INCLUDE Parameter Arbitrary Command Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server includes a CGI script that allows for arbitrary
shell command execution." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the installed version of TWiki allows an
attacker, by manipulating input to the 'rev' parameter, to execute
arbitrary shell commands on the remote host subject to the privileges
of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://twiki.org/cgi-bin/view/Codev/SecurityAlertExecuteCommandsWithInclude" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix listed in the vendor advisory." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );
script_end_attributes();

 
  script_summary(english:"Checks for INCLUDE function command execution vulnerability in TWiki");
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("twiki_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("Settings/ParanoidReport");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);
port = get_http_port(default:80);

# Test an install.
install = get_kb_item(string("www/", port, "/twiki"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if ( ver =~ "^(0[123] Sep 2004|01 Feb 2003)$") {
    security_warning(port);
    exit(0);
  }
}
