#
# (C) Tenable Network Security, Inc.
#

# Refs: http://www.frog-man.org/tutos/WihPhoto.txt
#
# From: "Frog Man" <leseulfrog@hotmail.com>
# To: bugtraq@securityfocus.com
# Subject: [VulnWatch] WihPhoto (PHP)
# Message-ID: <F1195Iw7bEtfjKNE0500000ecbd@hotmail.com>
#


include("compat.inc");

if(description)
{
 script_id(11274);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2003-1239");
 script_bugtraq_id(6929);
 script_xref(name:"OSVDB", value:"53611");
 
 script_name(english:"WihPhoto sendphoto.php Traversal Arbitrary File Access");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by an
information disclosure flaw." );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote host mail any file contained on its
hard drive by using a flaw in WihPhoto's 'util/email.php' script." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/312892" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Checks for the presence of remotehtmlview.php");
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


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);



function check(loc)
{
 local_var r, req;

 req = http_get(item:string(loc, "/start.php"),
 		port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( r == NULL )exit(0);
 if(egrep(pattern:"WihPhoto 0\.([0-9][^0-9]|[0-7][0-9][^0-9]|8[0-6][^0-9])", string:r))
 {
 	security_warning(port);
	exit(0);
 }
}


dir = make_list(cgi_dirs());
dirs = make_list();
foreach d (dir)
 dirs = make_list(dirs, string(d, "/wihphoto"), string(d, "/WihPhoto"));

dirs = make_list(dirs, "/wihphoto", "/WihPhoto");


foreach dir (dirs)
{
check(loc:dir);
}
