#
# (C) Tenable Network Security, Inc.
#

# ref: http://www.kernelpanik.org/docs/kernelpanik/wordpressadv.txt
#


include("compat.inc");

if(description)
{
 script_id(11703);
 script_version ("$Revision: 1.14 $");
 script_bugtraq_id(7785);
 script_xref(name:"OSVDB", value:"4611"); 
 script_xref(name:"OSVDB", value:"4610"); 

 script_name(english:"WordPress < 0.72 RC1 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains PHP scripts that allow for arbitrary
PHP code execution and local file disclosure as well as SQL injection
attacks." );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote host include php files hosted on a
third-party server using the WordPress CGI suite which is installed
(which is also vulnerable to a SQL injection attack). 

An attacker may use this flaw to inject arbitrary PHP code in the
remote host and gain a shell with the privileges of the web server or
to take the control of the remote database." );
 script_set_attribute(attribute:"see_also", value:"http://www.kernelpanik.org/docs/kernelpanik/wordpressadv.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to 0.72 RC1 or higher." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for the presence of WordPress");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("wordpress_detect.nasl");
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
if(!can_host_php(port:port))exit(0);



function check_php_inc(loc)
{
 local_var r, req;
 req = http_get(item:string(loc, "/wp-links/links.all.php?abspath=http://xxxxxxxx"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( r == NULL )exit(0);
 if("http://xxxxxxxx/blog.header.php" >< r)
 {
 	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
 }
}

function check_sql_inj(loc)
{
 local_var r, req;
 req = http_get(item:string(loc, "/index.php?posts='"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( r == NULL )exit(0);
 if("mysql_fetch_object()" >< r)
 {
 	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
 }
}




# Test an install.
install = get_kb_item(string("www/", port, "/wordpress"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];

 check_php_inc(loc:loc);
 check_sql_inj(loc:loc);
}
