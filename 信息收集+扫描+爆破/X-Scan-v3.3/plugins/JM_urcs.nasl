#
# This script was written by J.Ml?zian?ski <j?eph[at]rapter.net>
# 
# 


include("compat.inc");

if(description)
{
 script_id(15405);
 script_version("$Revision: 1.12 $");
 name["english"] = "URCS Server Detection";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host may have been compromised." );
 script_set_attribute(attribute:"description", value:
"This host appears to be running Unmanarc Remote Control Server (URCS). 
While it does have some legitimate uses, URCS may also have been
installed silently as a backdoor, which may allow an intruder to gain
remote access to files on the remote system.  If this program was not
installed for remote management, then it means the remote host has
been compromised. 

An attacker may use it to steal files, passwords, or redirect ports on
the remote system to launch other attacks." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/projects/urcs" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ddf2497d" );
 script_set_attribute(attribute:"see_also", value:"http://securityresponse.symantec.com/avcenter/venc/data/backdoor.urcs.html" );
 script_set_attribute(attribute:"solution", value:
"Reinstall the operating system and files from backup unless URCS is
intended to be installed." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of the URCS Server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright(C) 2004-2009 J.Mlodzianowski");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/unknown", 3360);
 exit(0);
}

#
# The code starts here:
#

include("misc_func.inc");
include('global_settings.inc');

if ( ! thorough_tests || get_kb_item("global_settings/disable_service_discovery")  )
{
 port = 3360;
}
else
{
 port = get_unknown_svc(3360);
 if ( ! port ) exit(0);
}
# Default port for URCS Server is 3360
# Default port for URCS Client is 1980
 if (get_port_state(port))
{
 soc= open_sock_tcp(port);
 if(soc)
{
 send(socket:soc, data:'iux');
 r = recv(socket:soc, length:817);
 if ( "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" >< r ) 
	security_hole(port);
 close(soc);
 }
} 
