#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(17256);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2005-0645", "CVE-2005-2393");
  script_bugtraq_id(12691, 14328);
  script_xref(name:"OSVDB", value:"14309");
  script_xref(name:"OSVDB", value:"18082");
  script_xref(name:"OSVDB", value:"18081");
 
  script_name(english:"CuteNews <= 1.3.6 Multiple XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains several PHP scripts that are prone to
multiple flaws, including possible arbitrary PHP code execution." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the remote host is running a version
of CuteNews that allows an attacker to inject arbitrary script through
the variables 'X-FORWARDED-FOR' or 'CLIENT-IP' when adding a comment. 
On one hand, an attacker can inject a client-side script to be
executed by an administrator's browser when he/she chooses to edit the
added comment.  On the other, an attacker with local access could
leverage this flaw to run arbitrary PHP code in the context of the web
server user. 

Additionally, it suffers from a cross-site scripting flaw involving
the 'search.php' script." );
 script_set_attribute(attribute:"see_also", value:"http://www.kernelpanik.org/docs/kernelpanik/cutenews.txt" );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/cutenews.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_summary(english:"Checks for multiple vulnerabilities in CuteNews <= 1.3.6");

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("cutenews_detect.nasl");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/cutenews"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # 1.3.6 is known to be affected; previous versions likely are too.
  if (ver =~ "^(0.*|1\.([0-2].*|3[^.]?|3\.[0-6]))") {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
