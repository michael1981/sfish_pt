#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11058);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-1999-0626");
 script_xref(name:"OSVDB", value:"856");
 
 script_name(english:"RPC rusers Remote Information Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to enumerate logged in users." );
 script_set_attribute(attribute:"description", value:
"The rusersd RPC service is running.  It provides an attacker interesting
information such as how often the system is being used, the names of the
users, and more." );
 script_set_attribute(attribute:"solution", value:
"Disable this service if not needed." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

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

include("sunrpc_func.inc");


RPC_PROG = 100002;
RUSERSPROC_NAME = 0x02;

port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_UDP);

if(port)
{
 soc = open_sock_udp (port);
 if (!soc) exit(0);
 udp = TRUE;

 data = NULL;

 packet = rpc_packet (prog:RPC_PROG, vers:2, proc:RUSERSPROC_NAME, data:data, udp:udp);

 data = rpc_sendrecv (socket:soc, packet:packet, udp:udp);
 if (isnull(data) || (strlen(data) < 4))
   exit(0);

 register_stream(s:data);

 users = xdr_getdword();
 report = NULL;

 for (i=0; i<users; i++)
 {
  term = xdr_getstring();
  user = xdr_getstring();
  disp = xdr_getstring();

  xdr_getdword();
  xdr_getdword();

  report += string (user, " (", term, ") from ", disp, "\n");
 }

 if (report)
 {
  report = string (
		"Using rusers, we could determine that the following users are logged in :\n\n",
		report
		);
  security_warning(port, extra:report);
 }
 else
  security_warning(port, extra:report);
}
