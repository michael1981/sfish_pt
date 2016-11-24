#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10031);
 script_version ("$Revision: 1.22 $");

 script_xref(name:"OSVDB", value:"25");

 script_name(english:"RPC bootparamd Service Information Disclosure");
 script_summary(english:"Checks the presence of a RPC service");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The RPC service running on the remote host has an information\n",
     "disclosure vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The bootparamd RPC service is running.  It is used by diskless clients\n",
      "to get the necessary information needed to boot properly.\n\n",
      "If an attacker uses the BOOTPARAMPROC_WHOAMI and provides the correct\n",
      "address of the client, then he will get its NIS domain back from\n",
      "the server. Once the attacker discovers the NIS domain name, he may\n",
      "easily get your NIS password file."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:string(
     "Filter incoming traffic to prevent connections to the portmapper and\n",
     "to the bootparam daemon, or deactivate this service if you do not use it."
   )
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"RPC"); 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");


RPC_PROG = 100026;
tcp = 0;
port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
	port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_TCP);
	tcp = 1;
	}

if(port)
{
 set_kb_item(name:"rpc/bootparamd", value:TRUE);
 if(tcp)security_warning(port);
 else security_warning(port, protocol:"udp");
}
