#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18670);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2005-2204");
  script_bugtraq_id(14203);
  script_xref(name:"OSVDB", value:"17809");
  script_xref(name:"OSVDB", value:"17810");

  script_name(english:"SiteMinder 5.5 Multiple Script XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by
several cross-site scripting vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SiteMinder, an access-management solution
from Netegrity / Computer Associates. 

The installed version of SiteMinder suffers from several cross-site
scripting flaws in its 'smpwservicescgi.exe' and 'login.fcc' scripts.  
An attacker can exploit these flaws to inject arbitrary HTML and 
script code into the browsers of users of the affected application, 
thereby leading to cookie theft, site mis-representation, and similar 
attacks." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-07/0112.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-07/0163.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple cross-site scripting vulnerabilities in SiteMinder";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "');</script>";
exss = urlencode(str:xss);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Check whether the script exists.
  r = http_send_recv3(method: "GET", item:string(dir, "/smpwservicescgi.exe"), port:port);
  if (isnull(r)) exit(0);

  # If it does...
  if (egrep(string: r[2], pattern:'img alt="Logo" src=".+/siteminder_logo\\.gif')) {
    # Try to exploit one of the flaws.
    postdata = string(
      "SMAUTHREASON=0&",
      "TARGET=/&",
      "USERNAME=nessus&",
      'PASSWORD=">', exss, "&",
      "BUFFER=endl"
    );
    r = http_send_recv3(method: "POST", item: strcat(dir, "/smpwservicescgi.exe"), port: port,
 add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
 data: postdata);
    if (isnull(r)) exit(0);

    # There's a problem if we see our XSS.
    if (xss >< r[2]) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
