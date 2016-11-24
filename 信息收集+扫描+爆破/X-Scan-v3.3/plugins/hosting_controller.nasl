#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(11745);
 script_bugtraq_id(3808);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2002-0466");
 script_xref(name:"OSVDB", value:"10420");
 script_xref(name:"OSVDB", value:"10421");
 script_xref(name:"OSVDB", value:"10422");
 script_xref(name:"OSVDB", value:"10423");
 script_xref(name:"OSVDB", value:"10424");

 script_name(english:"Hosting Controller Multiple Script Arbitrary Directory Browsing");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running an application that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The Hosting Controller application resides on this server.  
This version is vulnerable to multiple remote exploits.  

At attacker may make use of this vulnerability and use it to
gain access to confidential data and/or escalate their privileges
on the Web server." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-01/0039.html" );
 script_set_attribute(attribute:"solution", value:
"Apply the vendor supplied patch." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );


script_end_attributes();

 
 summary["english"] = "Checks for the vulnerable instances of Hosting Controller";
 
 script_summary(english:summary["english"]);
 
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

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

flag = 0;
directory = "";

file[0] = "statsbrowse.asp";
file[1] = "servubrowse.asp";
file[2] = "browsedisk.asp";
file[3] = "browsewebalizerexe.asp";
file[4] = "sqlbrowse.asp";

for (i=0; file[i]; i = i + 1) {
	foreach dir (cgi_dirs()) {
   		if(is_cgi_installed_ka(item:string(dir, "/", file[i]), port:port)) {
			req = http_get(item:dir + "/" + file[i] + "?filepath=c:" + raw_string(0x5C,0x26) + "Opt=3", port:port);
			res = http_keepalive_send_recv(port:port, data:req);
			if(res == NULL) exit(0);
		       if ( (egrep(pattern:".*\.BAT.*", string:res)) || (egrep(pattern:".*\.ini.*", string:res)) ) {
					security_warning(port);
					exit(0);
				}
			}
   		}
	}
