#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(22364);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2006-4784", "CVE-2006-4785", "CVE-2006-4786");
  script_bugtraq_id(19995, 20085);
  script_xref(name:"OSVDB", value:"28792");
  script_xref(name:"OSVDB", value:"28793");
  script_xref(name:"OSVDB", value:"28794");
  script_xref(name:"OSVDB", value:"28795");
  script_xref(name:"OSVDB", value:"28796");
  script_xref(name:"OSVDB", value:"28797");
  script_xref(name:"OSVDB", value:"28798");
  script_xref(name:"OSVDB", value:"28800");
  script_xref(name:"OSVDB", value:"28801");
  script_xref(name:"OSVDB", value:"30841");

  script_name(english:"Moodle < 1.6.2 Multiple Vulnerabilities");
  script_summary(english:"Checks if Moodle's jumpto.php requires a sesskey");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that suffers from
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Moodle fails to sanitize user-supplied input
to a number of parameters and scripts.  An attacker may be able to
leverage these issues to launch SQL injection and cross-site scripting
attacks against the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/446227/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://docs.moodle.org/en/Release_Notes#Moodle_1.6.2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Moodle version 1.6.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("moodle_detect.nasl");
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

# Test an install.
install = get_kb_item(string("www/", port, "/moodle"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Request a redirect.
  xss = "nessus.php?";
  r = http_send_recv3(method: "GET", 
    item:string(dir, "/course/jumpto.php?jump=", urlencode(str:xss)), 
    port:port, follow_redirect: 0
  );
  if (isnull(r)) exit(0);

  # There's a problem if...
  if (
    # we get a session cookie for Moodle and...
    "MoodleSession=" >< r[0] &&
    # we're redirected
    string("location.replace('", xss, "')") >< r[2]
  ) {
     security_hole(port);
     set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
     set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    }
}
