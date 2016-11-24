#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title, touched-up output (7/03/09)


include("compat.inc");

if(description)
{
 script_id(14377);
 script_version ("$Revision: 1.5 $");
 script_name(english:"Arkoon Appliance Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is a firewall." );
 script_set_attribute(attribute:"description", value:
"The remote host has the three TCP ports 822, 1750, 1751
open.

It's very likely that this host is an Arkoon security dedicated
appliance with ports

 TCP/822  dedicated to ssh service
 TCP/1750 dedicated to Arkoon Manager
 TCP/1751 dedicated to Arkoon Monitoring

Letting attackers know that you are using an Arkoon 
appliance will help them to focus their attack or will 
make them change their strategy. 

You should not let them know such information." );
 script_set_attribute(attribute:"see_also", value:"http://www.arkoon.net/" );
 script_set_attribute(attribute:"solution", value:
"Do not allow any connection on the firewall itself, except 
for the firewall protocol, and allow that for trusted 
sources only.

If you have a router which performs packet filtering, then 
add ACL that disallows the connection to these ports for 
unauthorized systems." );
 script_set_attribute(attribute:"risk_factor", value:"Low" );

script_end_attributes();

 script_summary(english:"Determines if the remote host is an Arkoon");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"Firewalls");
 script_require_ports(822,1750,1751,1752);
 exit(0);
}

#
# The script code starts here
#

if((get_port_state(822))&&
   (get_port_state(1750))&&
   (get_port_state(1751)))
{
 
 soc1 = open_sock_tcp(822);
 if(!soc1)exit(0);
 banner = recv_line(socket:soc1, length:1024);
 close(soc1);
 #SSH-1.5-SSF
 if (!(egrep(pattern:"SSH-[0-9.]+-SSF",string:banner)))
 exit(0);
 
 soc2 = open_sock_tcp(1750);
 if(!soc2)exit(0);
 close(soc2);

 soc3 = open_sock_tcp(1751);
 if(!soc3)exit(0);
 close(soc3);
 
 # post the warning on every port
 security_note(0);
}
exit(0);
