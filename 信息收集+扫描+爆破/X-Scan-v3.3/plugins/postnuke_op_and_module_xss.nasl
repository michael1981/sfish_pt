#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(18006);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2005-1049");
  script_bugtraq_id(13075, 13076);
  script_xref(name:"OSVDB", value:"15369");
  script_xref(name:"OSVDB", value:"15370");

  script_name(english:"PostNuke < 0.760 RC4 Multiple Script XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to cross-
site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The version of PostNuke installed on the remote host fails to properly
sanitize user input through the 'op' parameter of the 'user.php'
script and the 'module' parameter of the 'admin.php' script before
using it in dynamically generated content.  An attacker can exploit
this flaw to inject arbitrary HTML and script code into the browser of
unsuspecting users, leading to disclosure of session cookies and the
like." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-04/0112.html" );
 script_set_attribute(attribute:"see_also", value:"http://community.postnuke.com/Article2679.htm" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 0.760 RC4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  summary["english"] = "Checks for op and module parameters cross-site scripting vulnerabilities in PostNuke";
  script_summary(english:summary["english"]);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("cross_site_scripting.nasl", "postnuke_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# - A simple alert to display "Nessus was here".
xss = "<script>alert('Nessus was here');</script>";
#   nb: the url-encoded version is what we need to pass in.
exss = "%3Cscript%3Ealert('Nessus%20was%20here')%3B%3C%2Fscript%3E";
n = 0;
cgi[n] = "/admin.php"; qs[n++] = "module=%22%3E" + exss + "&op=main&POSTNUKESID=355776cfb622466924a7096d4471a480";
cgi[n] = "/user.php"; qs[n++] = "op=%22%3E" + exss + "&module=NS-NewUser&POSTNUKESID=355776cfb622466924a7096d4471a480";

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/postnuke"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  # Try to exploit the flaws.
  for (i = 0; i < n; i ++) {
    if (test_cgi_xss(port: port, dirs: make_list(dir), cgi: cgi[i], qs: qs[i], pass_str: xss)) exit(0);
  }
}
