#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(11046);
 script_cve_id("CVE-2002-2006");
 script_xref(name:"OSVDB", value:"849");
 script_bugtraq_id(4575);
 script_version("$Revision: 1.29 $");
 script_name(english:"Apache Tomcat TroubleShooter Servlet Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a path disclosure issue." );
 script_set_attribute(attribute:"description", value:
"The default installation of Apache Tomcat includes various sample JSP
pages and servlets.  One of these, the 'TroubleShooter' servlet,
discloses Tomcat's installation directory when accessed directly." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-04/0311.html" );
 script_set_attribute(attribute:"solution", value:
"Example files should not be left on production servers." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 summary["english"] = "Tests whether the Apache Tomcat TroubleShooter Servlet is installed";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Matt Moore");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl","http_version.nasl");
 script_require_ports("Services/www", 80, 8080);
 script_require_keys("www/apache");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if(! port || ! get_port_state(port)) exit(0);

banner = get_http_banner(port: port);
if (banner && "Apache" >!< banner && 
   ("Tomcat" >!<  banner || "Apache-Coyote" >!< banner))
 exit(0);

url = "/examples/servlet/TroubleShooter";
req = http_get(item:url, port:port);
r =   http_keepalive_send_recv(port:port, data:req);
confirmed = string("TroubleShooter Servlet Output"); 
confirmed_too = string("hiddenValue");
if ((confirmed >< r) && (confirmed_too >< r)) 	
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "The 'TroubleShooter' servlet is accessible as :\n",
      "\n",
      "  ", build_url(port:port, qs:url), "\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
