#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12087);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2004-2550");
 script_bugtraq_id(9801);
 script_xref(name:"OSVDB", value:"4132");
 
 script_name(english:"SandSurfer < 1.7.1 XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is prone to multiple
cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SandSurfer, a web-based time keeping
application. 

A vulnerability has been disclosed in all versions of this software,
up to version 1.7.0 (included) which may allow an attacker to use it
to perform cross-site scripting attacks against third-party users." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/forum/forum.php?forum_id=356882" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SandSurfer 1.7.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );


script_end_attributes();

 script_summary(english:"Checks for SandSurfer");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc."); 
 script_family(english:"CGI abuses : XSS");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

foreach d ( cgi_dirs() )
{
 # SandSurfer installs under $prefix/cgi-bin/login.cgi
 req = http_get(item:string(d, "/cgi-bin/login.cgi"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if( egrep(pattern:"SandSurfer (0\.|1\.([0-5]\.|7\.1))", string:res)){
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
 }
 req = http_get(item:string(d, "/login.cgi"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if( egrep(pattern:"SandSurfer (0\.|1\.([0-6]\.|7\.0))", string:res)){
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
 }
}
