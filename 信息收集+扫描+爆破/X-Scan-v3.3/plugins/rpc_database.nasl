#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10214);
 script_version ("$Revision: 1.14 $");

 script_name(english:"RPC database Service Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"A deprecated RPC service is running." );
 script_set_attribute(attribute:"description", value:
"The database RPC service is running.  If you do not use this 
service, then you should disable it as it may become a security
threat in the future, if a vulnerability is discovered." );
 script_set_attribute(attribute:"solution", value:
"Disable this service if you do not use it, or filter
incoming traffic to this port" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_end_attributes();
 
 script_summary(english:"checks the presence of a RPC service");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"RPC"); 
 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}
#
# The script code starts here
#


include("misc_func.inc");
include('global_settings.inc');

if ( report_paranoia < 2 ) exit(0);



RPC_PROG = 100016;
tcp = 0;
port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
	port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_TCP);
	tcp = 1;
	}

if(port)
{
 if(tcp)security_note(port);
 else security_note(port, protocol:"udp");
}
