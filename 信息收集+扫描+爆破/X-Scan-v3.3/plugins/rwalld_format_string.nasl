#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10950);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2002-0573");
 script_bugtraq_id(4639);
 script_xref(name:"OSVDB", value:"778");
 script_xref(name:"IAVA", value:"2002-t-0009");
 
 script_name(english:"Solaris rpc.rwalld Remote Format String Arbitrary Code Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"An RPC service is running." );
 script_set_attribute(attribute:"description", value:
"The rpc.walld RPC service is running.  Some versions of this server 
allow an attacker to gain root access remotely, by consuming the 
resources of the remote host then sending a specially formed packet 
with format strings to this host.

Solaris 2.5.1, 2.6, 7, 8 and 9 are vulnerable to this issue. 
Other operating systems might be affected as well.

*** Nessus did not check for this vulnerability, so this might be a 
*** false positive" );
 script_set_attribute(attribute:"solution", value:
"Deactivate this service." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english: "Checks the presence of a RPC service");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english: "RPC");
 if ( ! defined_func("bn_random") )
 	script_dependencie("os_fingerprint.nasl", "rpc_portmap.nasl");
 else
 	script_dependencie("os_fingerprint.nasl", "rpc_portmap.nasl", "solaris251_112891.nasl", "solaris251_x86_112892.nasl", "solaris26_112893.nasl", "solaris26_x86_112894.nasl", "solaris7_112899.nasl", "solaris7_x86_112900.nasl", "solaris8_112846.nasl", "solaris8_x86_112847.nasl", "solaris9_112875.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");

if ( report_paranoia < 2 ) exit(0);

if ( get_kb_item("BID-4639") ) exit(0);
os =  get_kb_item("Host/OS");
if ( os && egrep(pattern:"Sun Solaris 1[0-9]", string:os)) exit(0);


#
# This is kinda lame but there's no way to remotely determine if
# this service is vulnerable to this flaw.
# 
RPC_PROG = 100008;
tcp = 0;
port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
	port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_TCP);
	tcp = 1;
	}

if(port)
{
 if(tcp)security_hole(port);
 else security_hole(port, protocol:"udp");
}
