#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# Modifications by Tenable Network Security :
# -> Check for an existing .jsp file, instead of /default.jsp
# -> Expect a jsp signature
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(11724);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2000-0682");
 script_bugtraq_id(1518);
 script_xref(name:"OSVDB", value:"1481");
 
 script_name(english:"BEA WebLogic FileServlet Source Code Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to an information disclosure attack." );
 script_set_attribute(attribute:"description", value:
"The version of the WebLogic web application installed on the remote
host contains a flaw such that by inserting a /ConsoleHelp/ into a
URL, critical source code files may be viewed." );
 script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technology/deploy/security/wls-security/12.html" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate Service Pack as described in the vendor advisory
referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
 summary["english"] = "Checks for WebLogic file disclosures ";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO); 
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 John Lampe");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

jspfiles = get_kb_list(string("www/", port, "/content/extensions/jsp"));

if(isnull(jspfiles))jspfiles = make_list("default.jsp");
else jspfiles = make_list(jspfiles);

cnt = 0;

foreach file (jspfiles)
{ 
 req = http_get(item:"/ConsoleHelp/" + file, port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( "<%" >< res && "%>" >< res ) { security_warning(port); exit(0); }
 cnt ++;
 if(cnt > 10)exit(0);
}
