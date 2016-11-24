#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (4/13/2009)


include("compat.inc");

if(description)
{
 script_id(11732);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2002-0290");
 script_bugtraq_id(4124);
 script_xref(name:"OSVDB", value:"5335");
 
 script_name(english:"Netwin WebNews Webnews.exe Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that suffers from a buffer
overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running WebNews, which offers web-based
access to Usenet news. 

Some versions of WebNews are prone to a buffer overflow when
processing a query string with an overly-long group parameter.  An
attacker may be able to leverage this issue to execute arbitrary shell
code on the remote host subject to the permissions of the web server
user id." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-02/0186.html" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch made released by the vendor on February 14th, 2002 if
running Webnews 1.1 or older." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks for the Webnews.exe file");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 John Lampe");
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
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

flag = 0;
directory = "";

foreach dir (cgi_dirs()) {
   if(is_cgi_installed_ka(item:string(dir, "/Webnews.exe"), port:port)) {
  	flag = 1;
  	directory = dir;
  	break;
   } 
}
 
if (flag) security_warning(port);
