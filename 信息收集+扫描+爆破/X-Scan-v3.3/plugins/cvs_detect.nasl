#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10051);
 script_version ("$Revision: 1.16 $");

 script_name(english:"CVS pserver Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"A CVS pserver is listening on the remote port" );
 script_set_attribute(attribute:"description", value:
"CVS (Concurrent Versions System) is an open source versioning system.
A cvs server can be accessed either using third party tools (ie: rsh
or ssh), or via the 'pserver' protocol, which is unencrypted." );
 script_set_attribute(attribute:"solution", value:
"Use cvs on top of RSH or SSH if possible" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_end_attributes();
 
 script_summary(english:"Detects a CVS pserver");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_require_ports("Services/cvspserver", 2401);
 script_dependencies("find_service1.nasl");
 exit(0);
}

#
# The script code starts here
#
port = get_kb_item("Services/cvspserver");
if(!port)port = 2401;
if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
req = string("BEGIN AUTH REQUEST\n",
	"/\n",
	"\n",
	"A\n",
	"END AUTH REQUEST\n");
send(socket:soc, data:req);
r = recv_line(socket:soc, length:4096);
close(soc);
if("repository" >< r || "I HATE" >< r)
	security_note(port);
