#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(19545);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-2689", "CVE-2005-2690");
  script_bugtraq_id(14635, 14636);
  script_xref(name:"OSVDB", value:"18970");
  script_xref(name:"OSVDB", value:"18971");
  script_xref(name:"OSVDB", value:"18972");

  script_name(english:"PostNuke <= 0.760 RC4b Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to several
attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running PostNuke version 0.760 RC4b or
older.  These versions suffer from several vulnerabilities :

  - Multiple Cross-Site Scripting Vulnerabilities
    An attacker can inject arbitrary HTML and script 
    code into the browser of users by manipulating
    input to the 'moderate' parameter of the 
    'Comments' module and the 'htmltext' parameter
    of the 'user.php' script.

  - A SQL Injection Vulnerability
    The application fails to launder user-supplied
    input to the 'show' parameter in the
    'modules/Downloads/dl-viewdownload.php' module.
    Provided an attacker has admin rights, he can
    exploit this issue to manipulate SQL queries." );
 script_set_attribute(attribute:"see_also", value:"http://securityreason.com/achievement_securityalert/22" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-08/0288.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PostNuke version 0.760 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P" );
script_end_attributes();


  script_summary(english:"Detects multiple vulnerabilities in PostNuke <= 0.760 RC4b");

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("postnuke_detect.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# A simple alert.
xss = '<script>alert("' + SCRIPT_NAME + '")</script>';
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);

exploits = make_list(
  string(
    "/index.php?",
    "module=Comments&",
    "req=moderate&",
    "moderate=<center><h1>", exss
  ),
  string(
    "/user.php?",
    "op=edituser&",
    "htmltext=<h1>", exss
  )
);


# Test an install.
install = get_kb_item(string("www/", port, "/postnuke"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit one of the XSS flaws.
  foreach exploit (exploits) {
    r = http_send_recv3(method:"GET", item:string(dir, exploit), port:port);
    if (isnull(r)) exit(0);
    res = r[2];

    # It's a problem if we see our XSS.
    if (xss >< res) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
