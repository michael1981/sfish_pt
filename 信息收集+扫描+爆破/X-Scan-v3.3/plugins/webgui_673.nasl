#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19590);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-2837");
  script_bugtraq_id(14732);

  name["english"] = "WebGUI < 6.7.3 Multiple Command Execution Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is prone to arbitrary
code execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running WebGUI, a content management system from
Plain Black Software. 

According to its banner, the installed version of WebGUI on the remote
host fails to sanitize user-supplied input to various sources before
using it to run commands.  By leveraging these flaws, an attacker may
be able to execute arbitrary commands on the remote host within the
context of the affected web server userid." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1763907f" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WebGUI 6.7.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple command execution vulnerabilities in WebGUI < 6.7.3";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Get the initial page.
  res = http_get_cache(item:string(dir, "/"), port:port);
  if (res == NULL) exit(0);

  if (
    egrep(string:res, pattern:'<meta name="generator" content="WebGUI 6\\.([1-6]\\..*|7\\.[0-2])"') ||
    egrep(string:res, pattern:'^ +<!-- WebGUI 6\\.([1-6]\\..*|7\\.[0-2]) -->')
  ) {
    security_hole(port);
  }
}
