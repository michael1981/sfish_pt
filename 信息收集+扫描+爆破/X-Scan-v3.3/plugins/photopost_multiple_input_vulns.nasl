#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(17649);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-0928", "CVE-2005-0929");
  script_bugtraq_id(12920);
  script_xref(name:"OSVDB", value:"15096");
  script_xref(name:"OSVDB", value:"15097");
  script_xref(name:"OSVDB", value:"15098");
  script_xref(name:"OSVDB", value:"15099");
  script_xref(name:"OSVDB", value:"15100");

  script_name(english:"PhotoPost < 5.1 Multiple Input Validation Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
several vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of PhotoPost PHP installed on the remote host is prone to
multiple input validation vulnerabilities:

  o Multiple SQL Injection Vulnerabilities
    The application fails to properly sanitize user-input via
    the 'sl' parameter of the 'showmembers.php' script, and 
    the 'photo' parameter of the 'showphoto.php' script. An 
    attacker can exploit these flaws to manipulate SQL 
    queries, possibly destroying or revealing sensitive data.

  o Multiple Cross-Site Scripting Vulnerabilities
    The application fails to properly sanitize user-input via
    the 'photo' parameter of the 'slideshow.php' script, the
    'cat', 'password', 'si', 'ppuser', and 'sort' parameters
    of the 'showgallery.php' script, and the 'ppuser', 'sort', 
    and 'si' parameters of the 'showmembers.php' script.
    An attacker can exploit these flaws to inject arbitrary 
    HTML or code script in a user's browser in the context of 
    the affected web site, resulting in theft of 
    authentication data or other such attacks." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-03/0471.html" );
 script_set_attribute(attribute:"solution", value:
"The issues are reportedly fixed by upgrading to PhotoPost PHP version
5.1." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple input validation vulnerabilities in PhotoPost PHP";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("photopost_detect.nasl");
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
install = get_kb_item(string("www/", port, "/photopost"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try some SQL injection exploits.
  exploits = make_list(
    "/showmembers.php?sl='nessus",
    "/showphoto.php?photo='nessus"
  );
  foreach exploit (exploits) {
    r = http_send_recv3(method:"GET",item:string(dir, exploit), port:port);
    if (isnull(r)) exit(0);
    res = r[2];
    if (
      egrep(string:res, pattern:"argument is not a valid MySQL result resource") ||
      egrep(string:res, pattern:">MySQL error reported!<.+>Script:")
    ) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
