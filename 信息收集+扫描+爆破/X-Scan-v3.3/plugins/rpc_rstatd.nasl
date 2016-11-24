#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10227);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-1999-0624");

 script_name(english:"RPC rstatd Service Detection");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to leak information about the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the rstatd RPC service. This service provides
information such as :

 - the CPU usage
 - the system uptime
 - the network usage" );
 script_set_attribute(attribute:"solution", value:
"Disable this service if not needed." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();

 script_summary(english:"Checks the presence of a RPC service");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_family(english:"RPC"); 
 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}


#
# The script code starts here
#

include ("sunrpc_func.inc");

function uptime (sec)
{
 return string (sec/3600, "h ", (sec/60)%60, "m ", sec%60, "s");
}


RPC_PROG = 100001;
tcp = 0;
port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_UDP);
if (!port)
{
 port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_TCP);
 tcp = 1;
}


if(port)
{
 if(tcp)
 {
  soc = open_sock_tcp (port);
  if (!soc) exit(0);
  udp = FALSE;
 }
 else
 {
  soc = open_sock_udp (port);
  if (!soc) exit(0);
  udp = TRUE;
 }

 data = NULL;

 packet = rpc_packet (prog:RPC_PROG, vers:3, proc:0x01, data:data, udp:udp);

 data = rpc_sendrecv (socket:soc, packet:packet, udp:udp);
 if (isnull(data) || (strlen(data) != 104))
   exit(0);

 report = string (
	"uptime: ", uptime(sec:getdword(blob:data, pos:92) - getdword(blob:data, pos:84)),
	"\n",
	"cpu usage: ",
	"user ", getdword(blob:data,pos:0), ", ",
	"nice ", getdword(blob:data,pos:4), ", ",
	"system ", getdword(blob:data,pos:8), ", ",
	"idle ", getdword(blob:data,pos:12),
	"\n",
	"disk transfer: ",
	"d1 ", getdword(blob:data,pos:16), ", ",
	"d1 ", getdword(blob:data,pos:20), ", ",
	"d1 ", getdword(blob:data,pos:24), ", ",
	"d1 ", getdword(blob:data,pos:28),
	"\n",
	"memory: ",
	"pagein ", getdword(blob:data,pos:32), ", ",
	"pageout ", getdword(blob:data,pos:36), ", ",
	"swapin ", getdword(blob:data,pos:40), ", ",
	"swapout ", getdword(blob:data,pos:44)
	);

 if (tcp)
   security_note(port, extra:report);
 else
   security_note(port, protocol:"udp", extra:report);
}
