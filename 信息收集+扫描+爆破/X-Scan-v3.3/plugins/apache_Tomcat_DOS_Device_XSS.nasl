#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#      Also covers BugtraqID: 5193 (same Advisory ID#: wp-02-0008)
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(11042);
 script_bugtraq_id(5194);
 script_xref(name:"OSVDB", value:"845");
 script_version("$Revision: 1.21 $");
 script_name(english:"Apache Tomcat DOS Device Name XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a cross-site scripting issue." );
 script_set_attribute(attribute:"description", value:
"Apache Tomcat is the servlet container that is used in the official
Reference Implementation for the Java Servlet and JavaServer Pages
technologies. 

By making requests for DOS Device names it is possible to cause Tomcat
to throw an exception, allowing XSS attacks.  The exception also
reveals the physical path of the Tomcat installation." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat v4.1.3 beta or later." );
 script_set_attribute(attribute:"see_also", value:"http://www.westpoint.ltd.uk/advisories/wp-02-0008.txt" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 summary["english"] = "Tests for Apache Tomcat DOS Device name XSS Bug";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Matt Moore");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 8080);
 script_require_keys("www/apache");
 exit(0);
}

# Check starts here

include("http_func.inc");

port = get_http_port(default:8080);
if(!port || !get_port_state(port)) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);


banner = get_http_banner(port:port);

if (!egrep(pattern:"^Server: .*Tomcat/([0-3]\.|4\.0|4\.1\.[0-2][^0-9])", string:banner) ) exit(0);

req = http_get(item:"/COM2.<IMG%20SRC='JavaScript:alert(document.domain)'>", port:port);
soc = http_open_socket(port);
if(soc)
{ 
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 confirmed = string("JavaScript:alert(document.domain)"); 
 confirmed_too = string("java.io.FileNotFoundException");
 if ((confirmed >< r) && (confirmed_too >< r)) 	
	{
 		security_warning(port);
		set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	}
}
