#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: James McGlinn <james servers co nz>
#
#  This script is released under the GNU GPL v2
#


include("compat.inc");

if(description)
{
 script_id(15466);
 script_cve_id("CVE-2004-1570");
 script_bugtraq_id(11303);
 script_xref(name:"OSVDB", value:"10449");
 script_version ("$Revision: 1.8 $");
 
 script_name(english:"bBlog rss.php p Parameter SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web application is vulnerable to an SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote server runs a version of bBlog, a blogging system written in 
PHP and released under the GPL, which is as old as or older than version 
0.7.4.

The remote version of this software is affected by a SQL injection
attacks in the script 'rss.php'. This issue is due to a failure 
of the application to properly sanitize user-supplied input.

An attacker may use these flaws to execute arbitrary PHP code on this
host or to take the control of the remote database." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 0.7.4 or newer." );
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

 
 summary["english"] = "Check bBlog version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
		
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!port) exit(0);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


foreach dir (make_list(cgi_dirs(),  "/bblog"))
{
 buf = http_get(item:string(dir,"/index.php"), port:port);
 r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
 if( r == NULL )exit(0);
 if(egrep(pattern:"www\.bBlog\.com target=.*bBlog 0\.([0-6]\.|7\.[0-3][^0-9]).*&copy; 2003 ", string:r))
 {
   security_hole(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
 }
}
