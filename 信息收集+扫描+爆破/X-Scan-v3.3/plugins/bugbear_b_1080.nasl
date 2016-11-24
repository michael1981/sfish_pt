#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11733);

 script_version ("$Revision: 1.7 $");
 script_name(english:"Bugbear.B Worm Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has been compromised." );
 script_set_attribute(attribute:"description", value:
"The BugBear.B backdoor is listening on this port.  An attacker may
connect to it to retrieve secret information such as passwords, credit
card numbers, etc. 

The BugBear.B worm includes a keylogger and can kill antivirus and
firewall software.  It propagates through email and open Windows
shares." );
 script_set_attribute(attribute:"solution", value:
"- Use an Anti-Virus package to remove it.
- Close your Windows shares
- See http://www.symantec.com/avcenter/venc/data/w32.bugbear.b@mm.removal.tool.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Detect Bugbear.B Worm Detection";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(
  english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_require_ports(1080);
 script_dependencies("find_service1.nasl");
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");


#
# bugbear.b is bound to port 1080. It sends data which seems to
# be host-specific when it receives the letter "p"
#
port = 1080;
if (! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);
send(socket:soc, data:"p");
r = recv(socket: soc, length: 308);
close(soc);
if(!strlen(r))exit(0);


soc = open_sock_tcp(port);
if (! soc) exit(0);
send(socket: soc, data: "x");
r2 = recv(socket: soc, length: 308);
if(strlen(r2)) { exit(0); }
close(soc);





if(strlen(r) > 10 )
{
 security_hole(port); 
 register_service(port: port, proto: "bugbear_b");
 exit(0); 
}
