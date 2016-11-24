#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(32480);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2008-5225");
  script_bugtraq_id(29430);
  script_xref(name:"OSVDB", value:"45748");
  script_xref(name:"Secunia", value:"30426");

  script_name(english:"XEROX DocuShare dsweb Servlet Multiple XSS");
  script_summary(english:"Tries to inject script code into a user's view properties");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Tomcat Servlet that is affected by a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running DocuShare, a web-based document management
application from XEROX. 

The version of DocuShare installed on the remote host fails to
sanitize user input to the 'dsweb' servlet before including it in
dynamic HTML output.  An attacker may be able to leverage this issue
to inject arbitrary HTML and script code into a user's browser to be
executed within the security context of the affected site. 

Note that the application is also reportedly affected by two similar
issues, although Nessus has not checked for them." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/492766" );
 script_set_attribute(attribute:"see_also", value:"https://docushare.xerox.com/doug/dsweb/View/Collection-7503" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-06/0011.html" );
 script_set_attribute(attribute:"solution", value:
"Use the workaround described in the vendor advisory at least until a
patch is released." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);

exploit = string('1">', "<BODY ONLOAD=alert('", SCRIPT_NAME, "')>");


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/docushare", "/dsdn", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try the exploit.
  r = http_send_recv3(method: "GET", port: port, 
    item:string(dir, "/dsweb/Services/User-", urlencode(str:exploit)) );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we see our exploit in the error message
  # in the user view.
  if (
    string("Not found: User-", exploit, " or another in this batch") >< res &&
    "com.xerox.docushare.db.DbNoSuchObjectException" >< res
  )
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
