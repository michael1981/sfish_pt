#
# (C) Tenable Network Security
#



include("compat.inc");

if (description) {
  script_id(19593);
  script_version("$Revision: 1.5 $");

  script_bugtraq_id(14728);

  name["english"] = "PBLang < 4.66z Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains various PHP scripts that are prone to
information disclosure, message deletion, and privilege escalation." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PBLang, a bulletin board system that uses
flat files and is written in PHP. 

According to its banner, the version of PBLang installed on the remote
host allows an attacker to inject code and create a user with
administrative privileges, certain users to access restricted forums
without proper permissions, and authenticated users to delete other
users' private messages." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=353425" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PBLang 4.66z or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in PBLang < 4.66z";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Get the initial page.
  r = http_send_recv3(method:"GET", item:string(dir, "/index.php"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # Check the version number.
  if (
    egrep(string:res, pattern:'<A HREF="http://pblang\\.drmartinus\\.de/[^>]+>Software PBLang ([0-3]\\.|4\\.([0-5].*|6([0-5].*|6[a-y]?)))<') ||
    egrep(string:res, pattern:'<meta name="description" content=".+running with PBLang ([0-3]\\.|4\\.([0-5].*|6([0-5].*|6[a-y]?)))">')
  ) {
    security_hole(port);
    exit(0);
  }
}
