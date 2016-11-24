#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(17970);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-1011", "CVE-2005-1012");
  script_bugtraq_id(12985);
  script_xref(name:"OSVDB", value:"15238");
  script_xref(name:"OSVDB", value:"15239");

  script_name(english:"SiteEnable Multiple Input Validation Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is affected by
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the SiteEnable CMS package
that is prone to several vulnerabilities :

  - SQL Injection Vulnerability
    Due to a failure to properly sanitize user input to the 'sortby' 
    parameter of the 'content.asp' script, an attacker can 
    execute SQL queries against the underlying database.

  - Multiple Cross-Site Scripting Vulnerabilities
    An attacker can pass arbitrary HTML and script code through
    the 'contenttype' parameter (and likely others) of the 
    'content.asp' script to be executed in a user's browser in
    the context of the affected website." );
 script_set_attribute(attribute:"see_also", value:"http://securitytracker.com/alerts/2005/Apr/1013631.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_summary(english:"Checks for XSS and SQL injection vulnerabilities in SiteEnable");
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_asp(port:port)) exit(0);


# Check various directories for SiteEnable.
foreach dir (cgi_dirs()) {
  # Pull up goto.asp and look for a string identifying SiteEnable.
  req = http_get(item:string(dir, "/goto.asp"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it's SiteEnable.
  if ('A "gotourl=" parameter must be passed to this page' >< res) {
    # Try the exploit.
    req = http_get(
      item:string(
        dir, "/content.asp?",
        "CatId=&",
        "ContentType=&",
        "keywoards=Contact&",
        "search=%3E&",
        "do_search=1&",
        # nb: cause a syntax error.
        "sortby=foo%20bar"
      ), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # If we get a database error, there's a problem.
    if (egrep(string:res, pattern:"Microsoft JET Database Engine.+error '80040e10'", icase:TRUE)) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
