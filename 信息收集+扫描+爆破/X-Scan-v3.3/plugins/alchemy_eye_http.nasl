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
 script_id(10818);
 script_bugtraq_id(3599);
 script_version("$Revision: 1.18 $");
 script_cve_id("CVE-2001-0871");
 script_xref(name:"OSVDB", value:"684");
 script_name(english:"Alchemy Eye/Network Monitor Traversal Arbitrary Command Execution");
 script_summary(english:"Determine if arbitrary commands can be executed by Alchemy Eye");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote command execution
vulnerability." );
 script_set_attribute(attribute:"description", value:
"Alchemy Eye and Alchemy Network Monitor are network management tools
for Microsoft Windows. The product contains a built-in HTTP server for
remote monitoring and control. This HTTP server allows arbitrary
commands to b e run on the server by a remote attacker." );
 script_set_attribute(attribute:"solution", value:
"Either disable HTTP access in Alchemy Eye, or require authentication
for Alchemy Eye. Both of these can be set in the Alchemy Eye
preferences." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 H D Moore & Drew Hintz ( http://guh.nu )");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_keys("www/alchemy");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

function check(req)
{
 local_var req, r, pat;

 req = http_get(item:req, port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if ( r == NULL ) exit(0);
 pat = "ACCOUNTS | COMPUTER"; 
 if(pat >< r) {
   	security_hole(port:port);
	exit(0);
 	}
 return(0);
}

dir[0] = "/PRN";
dir[1] = "/NUL";
dir[2] = "";

for(d=0;dir[d];d=d+1)
{
	url = string("/cgi-bin", dir[d], "/../../../../../../../../WINNT/system32/net.exe");
	check(req:url);
}
