#
# (C) Tenable Network Security, Inc.
#

# Ref (for the MITM attack) :
#  To: bugtraq@securityfocus.com
#  Subject: Microsoft Terminal Services vulnerable to MITM-attacks.
#  From: Erik Forsberg <forsberg+btq@cendio.se>
#  Date: 02 Apr 2003 00:05:44 +0200
#


include("compat.inc");

if(description)
{
 script_id(10940);
 script_version ("$Revision: 1.23 $");

 script_name(english:"Windows Terminal Services Enabled");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has Terminal Services enabled." );
 script_set_attribute(attribute:"description", value:
"Terminal Services allows a Windows user to remotely obtain a graphical
login (and therefore act as a local user on the remote host). 

If an attacker gains a valid login and password, he may be able to use
this service to gain further access on the remote host.  An attacker
may also use this service to mount a dictionary attack against the
remote host to try to log in remotely. 

Note that RDP (the Remote Desktop Protocol) is vulnerable to
Man-in-the-middle attacks, making it easy for attackers to steal the
credentials of legitimate users by impersonating the Windows server." );
 script_set_attribute(attribute:"solution", value:
"Disable Terminal Services if you do not use it, and do not allow this
service to run across the Internet." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();

 script_summary(english:"Connects to the remote terminal server");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencie("find_service1.nasl");
 script_require_ports(3389);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = 3389;
if(get_port_state(port))
{
   soc = open_sock_tcp(port);
   if(!soc)exit(0);
   str = raw_string(0x03, 0x00, 0x00, 0x0B, 0x06, 0xE0,
       		    0x00, 0x00, 0x00, 0x00, 0x00);
   send(socket:soc, data:str);
   r = recv(socket:soc, length:11);
   if(!r)exit(0);

   if(ord(r[0]) == 0x03) {
     security_note(port);
     register_service(port:port, proto:"msrdp");
   }
   close(soc);
}
