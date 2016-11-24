#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(11747);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2001-0958");
 script_bugtraq_id(3327);
 script_xref(name:"OSVDB", value:"6150");
 script_xref(name:"OSVDB", value:"6151");
 script_xref(name:"OSVDB", value:"6152");
 script_xref(name:"OSVDB", value:"6153");
 script_xref(name:"OSVDB", value:"6154");
 script_xref(name:"OSVDB", value:"6155");
 
 script_name(english:"Trend Micro Emanager Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a plug-in for InterScan." );
 script_set_attribute(attribute:"description", value:
"The Trend Micro Emanager software resides on this server.
Some versions of this software have DLLs with multiple
vulnerabilities, including buffer overflows." );
 script_set_attribute(attribute:"see_also", value:"http://www.trendmicro.com/en/home/us/enterprise.htm" );
 script_set_attribute(attribute:"solution", value:
"Make sure you are using the latest version of this software." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

script_end_attributes();

 
 script_summary(english:"Check for certain Trend Micro dlls");
 
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
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

flag = flag2 = 0;
directory = "";

file[0] = "register.dll";
#file[1] = "ContentFilter.dll";
#file[2] = "SFNofitication.dll";
#file[3] = "TOP10.dll";
#file[4] = "SpamExcp.dll";
#file[5] = "spamrule.dll";

for (i=0; file[i]; i = i + 1) {
foreach dir (cgi_dirs()) {
   if ( "eManager" >< dir )  flag2 = 1;
   if(is_cgi_installed_ka(item:string(dir, "/", file[i]), port:port)) {
  	flag = 1;
  	directory = dir;
  	break;
   } 
}
}

if ( (! flag2) && (! flag) )  {
	dirs[0] = "/eManager/Email%20Management/";
	dirs[1] = "/eManager/Content%20Management/";
        for (i=0; dirs[i]; i = i + 1) {
		for (q=0; file[q] ; q = q + 1) {
			if(is_cgi_installed_ka(item:string(dirs[i], file[q]) , port:port)) {
				security_note(port);
				exit(0);
			}
   		}
	}	
 }

if (flag) security_note (port);
