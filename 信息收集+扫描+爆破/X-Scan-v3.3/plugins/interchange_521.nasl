#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(19779);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-3072", "CVE-2005-3073");
  script_bugtraq_id(14931);
  script_xref(name:"OSVDB", value:"19652");
  script_xref(name:"OSVDB", value:"19653");

  script_name(english:"Interchange < 5.0.2 / 5.2.1 Multiple Vulnerabilities (SQLi, Code Exe)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server uses an application server that may be prone to
SQL injection or cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Interchange, an open-source
application server that handles state management, authentication,
session maintenance, click trails, filtering, URL encodings, and
security policy. 

According to its banner, the installed version of Interchange fails to
sanitize input passed through to the 'forum/submit.html' page, which
may lead to either SQL injection or cross-site scripting attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c36476c6" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?354ffb6a" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Interchange 5.0.2 / 5.2.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in Interchange < 5.0.2 / 5.2.1";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
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


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Look for the admin login page -- it has a version number.
  req = http_get(item:string(dir, "/admin/login.html"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If ...
  if (
    # it looks like Interchange's admin login page and...
    egrep(string:res, pattern:'^<FORM ACTION=".+/process" METHOD=POST name=login>') &&
    '<INPUT TYPE=hidden NAME=mv_nextpage VALUE="admin/index">' >< res &&
    # the version number is < 5.0.2 / 5.2.0.
    egrep(string:res, pattern:"^ +([0-4]\.|5\.(0\.[01]|2\.0)) &copy; 20.+ Interchange Development Group&nbsp;")
  ) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
