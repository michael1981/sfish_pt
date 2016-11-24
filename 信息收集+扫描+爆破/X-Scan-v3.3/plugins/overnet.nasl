#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11845);
 script_version("$Revision: 1.8 $");

 script_name(english:"Overnet Detection");

 script_set_attribute(attribute:"synopsis", value:
"A Peer-to-Peer client appears to be running on the remote
host." );
 script_set_attribute(attribute:"description", value:
"The remote server seems to be a Overnet Peer-to-Peer client,
which may not be suitable for a business environment." );
 script_set_attribute(attribute:"solution", value:
"Uninstall this software" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_end_attributes();

 script_summary(english:"Determines if the remote system is running Overnet");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Peer-To-Peer File Sharing");
 exit(0);
}




port = 5768;
if(!get_udp_port_state(port))exit(0);
req = raw_string(0xE3,0x0C,0xAB,0xA3,0xD7,0x95,0x39,0xE5,0x8C,0x49,0xEA,0xAB,0xEB,0x4F,0xA5,0x50,0xB8,0xF4,0xDD,0x9A,0x3E,0xD0,0x89,0x1F,0x00);
soc = open_sock_udp(port);
if ( ! soc ) exit(0);
send(socket:soc, data:req);
r = recv(socket:soc, length:256);
if (r) security_note(port);
exit(0);
