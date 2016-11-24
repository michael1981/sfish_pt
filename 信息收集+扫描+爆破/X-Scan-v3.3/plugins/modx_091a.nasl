#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21235);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2006-1820", "CVE-2006-1821");
  script_bugtraq_id(17532, 17533);
  script_xref(name:"OSVDB", value:"24697");
  script_xref(name:"OSVDB", value:"24698");

  script_name(english:"MODx < 0.9.1a Multiple Vulnerabilities");
  script_summary(english:"Tries to exploit a XSS flaw in MODx");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MODx, a content management system written
in PHP. 

The version of MODx installed on the remote host fails to sanitize
input to the 'id' parameter of the 'index.php' script before using it
to generate dynamic HTML output.  An unauthenticated attacker can
exploit this to inject arbitrary script and HTML into a user's
browser. 

Also, the same lack of input sanitation reportedly can be leveraged to
launch directory traversal attacks against the affected application,
although exploitation may only be successful if the affected host is
running Windows and if PHP's 'magic_quotes_gpc' setting is disabled." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/431010/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://modxcms.com/forums/index.php/topic,3982.0.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MODx version 0.9.1a or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);
if (!can_host_php(port:port)) exit(0);


# A simple alert.
xss = string("<script>alert(", SCRIPT_NAME, ")</script>");


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/modx", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue.
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/index.php?",
      "id=2", urlencode(str:xss)
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "the web server did not anwer");
  res = w[2];

  # There's a problem if we see our XSS.
  if (string("WHERE (sc.id=2", xss, " )") >< res)
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
