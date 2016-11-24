#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, touched up description (6/12/09)


include("compat.inc");

if(description)
{
 script_id(10855);
 script_version("$Revision: 1.17 $");

 script_cve_id("CVE-2002-0568");
 script_bugtraq_id(4290);
 script_xref(name:"OSVDB", value:"3423");
 script_xref(name:"IAVA", value:"2002-t-0006");

 script_name(english:"Oracle Applicatoin Server XSQLServlet XSQLConfig.xml Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"Sensitive data can be read on the remote host." );
 script_set_attribute(attribute:"description", value:
"It is possible to read the contents of the XSQLConfig.xml file which contains 
sensitive information." );
 script_set_attribute(attribute:"see_also", value:"http://www.nextgenss.com/papers/hpoas.pdf (Hackproofing Oracle9iAS)" );
 script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/" );
 script_set_attribute(attribute:"solution", value:
"Move this file to a safer location and update your servlet engine's 
configuration file to reflect the change." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"Tests for presence of XSQLConfig.xml");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Matt Moore");
 script_family(english:"Databases");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 exit(0);
}

# Check starts here

include("http_func.inc");

port = get_http_port(default:80);



if(get_port_state(port))
{
 req = http_get(item:"/xsql/lib/XSQLConfig.xml",
 		port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 tip = string("On a PRODUCTION system, under no circumstances should this confi
guration file reside in a directory that is browsable through the virtual path
 of your web server.");

if(tip >< r)
 {
 http_close_socket(soc);
 security_note(port);
 }
else
 {
 req = http_get(item:"/servlet/oracle.xml.xsql.XSQLServlet/xsql/lib/XSQLConfig.xml", port:port);
 soc = http_open_socket(port);
 if(soc)
  {
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  if(tip >< r)	
 	security_note(port);

   }
  }
 }
}
