#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10223);
 script_version ("$Revision: 1.32 $");

 script_name(english:"RPC portmapper Service Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"An ONC RPC portmapper is running on the remote host." );
 script_set_attribute(attribute:"description", value:
"The RPC portmapper is running on this port.

The portmapper allows someone to get the port number of each RPC
service running on the remote host by sending either multiple lookup
requests or a DUMP request." );
 script_set_attribute(attribute:"risk_factor", value: "None" );
 script_set_attribute(attribute:"solution", value: "n/a" );

script_end_attributes();
 
 script_summary(english:"Gets the port of the remote rpc portmapper");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_family(english:"RPC"); 
 script_dependencies("ping_host.nasl");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("sunrpc_func.inc");

# the portmaper
RPC_PROG = 100000;

port = 0;
kb_registered = 0;

if ( thorough_tests )
 ports = make_list(111, 32771);
else
 ports = make_list(111);

foreach p (ports)
{
 if(get_udp_port_state(p))
   port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_UDP, portmap:p);
 else
   port = 0;
	  
 if(port)
 {
  if ( p != 111 ) set_kb_item(name:"rpc/portmap/different_port", value:p);

  if(kb_registered == 0)
  {
   set_kb_item(name:"rpc/portmap", value:p);
   kb_registered = 1;
  }
 register_service(port: p, proto: "rpc-portmapper", ipproto:"udp");
 security_note(port: p, proto: "udp");
 }
}
