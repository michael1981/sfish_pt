#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19314);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2005-2430");
  script_bugtraq_id(14405);
  script_xref(name:"OSVDB", value:"18299");
  script_xref(name:"OSVDB", value:"18300");
  script_xref(name:"OSVDB", value:"18301");
  script_xref(name:"OSVDB", value:"18302");
  script_xref(name:"OSVDB", value:"18303");
  script_xref(name:"OSVDB", value:"18304");

  script_name(english:"GForge <= 4.5 Multiple Script XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by
multiple cross-site scripting vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running GForge, an open-source software development
collaborative toolset using PHP and PostgreSQL. 

The installed version of GForge on the remote host fails to properly
sanitize user-supplied input to several parameters / scripts before
using it in dynamically generated pages.  An attacker can exploit
these flaws to launch cross-site scripting attacks against the
affected application." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/406723/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  script_summary(english:"Checks for multiple cross-site scripting vulnerabilities in Gforge <= 4.5");
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
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# A simple alert.
xss = '<script>alert("' + SCRIPT_NAME + '");</script>';


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit one of the flaws.
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/forum/forum.php?",
      "forum_id=", urlencode(str:string('">', xss))
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # There's a problem if we see our XSS as part of a PostgreSQL error.
  if (string('pg_atoi: error in "">', xss) >< res) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
