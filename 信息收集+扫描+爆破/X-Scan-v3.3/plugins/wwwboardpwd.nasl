#
# This cgi abuse script was written by Jonathan Provencher
# Ce script de scanning de cgi a ete ecrit par Jonathan Provencher
# <druid@balistik.net>
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (4/28/09)


include("compat.inc");

if(description)
{
 script_id(10321);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-1999-0953");
 script_bugtraq_id(649, 12453);
 script_xref(name:"OSVDB", value:"11874");
 
 script_name(english:"WWWBoard passwd.txt Authentication Credential Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that is prone to an
information disclosure attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running WWWBoard, a bulletin board system written
by Matt Wright. 

This board system comes with a password file (passwd.txt) installed
next to the file 'wwwboard.html'.  An attacker may obtain the contents
of this file and decode the password to modify the remote www board." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1998_3/0746.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1999-q3/0993.html" );
 script_set_attribute(attribute:"solution", value:
"Configure the wwwadmin.pl script to change the name and location of
'passwd.txt'." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks for the presence of /wwwboard/passwd.txt");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Jonathan Provencher");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
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

foreach dir(cgi_dirs())
{
 res = http_keepalive_send_recv(port:port, data:http_get(port:port, item:dir + "/wwwboard.html"), bodyonly:TRUE);
 if (res == NULL )exit(0);
 if ( "wwwboard.pl" >< res )
 {
 res = http_keepalive_send_recv(port:port, data:http_get(port:port, item:dir + "/passwd.txt"), bodyonly:TRUE);
 if ( strlen(res) && egrep(pattern:"^[A-Za-z0-9]*:[a-zA-Z0-9-_.]$", string:res))
	{
	 security_warning(port);
	 exit(0);
	}
 }
}

