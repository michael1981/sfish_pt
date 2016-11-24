#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(17258);
 script_version("$Revision: 1.10 $");

 script_name(english:"IDA Pro Disassembler Software Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a dissassembler program." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running the IDA Pro Disassembler Program." );
 script_set_attribute(attribute:"see_also", value:"http://www.datarescue.com/" );
 script_set_attribute(attribute:"solution", value:
"Check that this software fits with your corporate policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

script_end_attributes();

 script_summary(english:"IDA Pro Detection");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_require_udp_ports(23945);
 exit(0);
}


port = 23945;

req = raw_string(0x49,0x44,0x41,0x00,0x01,0x00,0x00,0x00) + crap(32);
match = raw_string(0x49,0x44,0x41,0x00,0x00);
soc = open_sock_udp(port);
if (! soc ) exit(0);
send (socket:soc, data:req);
r = recv(socket:soc, length:40, timeout:3);
if ( ! r ) exit(0);
if (match >< r)
	security_note(port);
