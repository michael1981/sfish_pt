#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#      Also covers BugtraqID: 5194 (same Advisory ID#: wp-02-0008)
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(11041);
 script_bugtraq_id(5193);
 script_version("$Revision: 1.28 $");
 script_cve_id("CVE-2002-0682");
 script_xref(name:"OSVDB", value:"4973");
 
 script_name(english:"Apache Tomcat /servlet Mapping XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a cross-site scripting issue." );
 script_set_attribute(attribute:"description", value:
"Apache Tomcat is the servlet container that is used in the official Reference 
Implementation for the Java Servlet and JavaServer Pages technologies.

By using the /servlet/ mapping to invoke various servlets / classes it
is possible to cause Tomcat to throw an exception, allowing XSS
attacks." );
 script_set_attribute(attribute:"solution", value:
"The 'invoker' servlet (mapped to /servlet/), which executes anonymous
servlet classes that have not been defined in a web.xml file should be
unmapped. 

The entry for this can be found in the
/tomcat-install-dir/conf/web.xml file." );
 script_set_attribute(attribute:"see_also", value:"http://www.westpoint.ltd.uk/advisories/wp-02-0008.txt" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 summary["english"] = "Tests for Apache Tomcat /servlet XSS Bug";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Matt Moore");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 8080);
 script_require_keys("www/apache");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);
if(!port)exit(0);

if(!get_port_state(port)) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

banner = get_http_banner(port:port);
if ("Tomcat" >!< banner && "Apache-Coyote" >!< banner)
  exit (0);


req = http_get(item:"/servlet/org.apache.catalina.ContainerServlet/<SCRIPT>alert(document.domain)</SCRIPT>", port:port);
r = http_keepalive_send_recv(port:port, data:req);
confirmed = string("<SCRIPT>alert(document.domain)</SCRIPT>"); 
confirmed_too = string("javax.servlet.ServletException");
  if ((confirmed >< r) && (confirmed_too >< r)) {
		security_warning(port);
		set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
