#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(18188);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2004-1570", "CVE-2004-1865", "CVE-2005-1309", "CVE-2005-1310");
  script_bugtraq_id(13397, 13398);
  script_xref(name:"OSVDB", value:"15754");
  script_xref(name:"OSVDB", value:"15755");
  script_xref(name:"OSVDB", value:"15756");

  script_name(english:"bBlog <= 0.7.4 Multiple Vulnerabilities (SQLi, XSS)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running bBlog, an open-source blog software
application. 

According to its banner, the remote version of this software suffers
from several vulnerabilities:

  - A SQL Injection Vulnerability
    It is reportedly possible to inject SQL statements through
    the 'postid' parameter of the 'index.php' script.

  - Multiple Cross-Site Scripting Vulnerabilities
    The application fails to properly sanitize user-supplied
    input through the blog entry title field and the comment 
    body text." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f0a35ed" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in bBlog <= 0.7.4";
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
if (!can_host_php(port:port)) exit(0);


# Search for bBlog.
foreach dir (cgi_dirs()) {
  # Grab the admin index.php -- by default it holds the version number.
  r = http_send_recv3(method:"GET", item:string(dir, "/bblog/index.php"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it's bBlog...
  if ("Welcome to bBlog" >< res || "<h1>bBlog</h1>" >< res) {
    if (egrep(string:res, pattern:"^bBlog \.([0-6].+|7\.[0-4])</a> &copy; 200")) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
