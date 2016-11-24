#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(21655);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2003-0813", "CVE-2004-0116", "CVE-2003-0807", "CVE-2004-0124");
 script_bugtraq_id(10121, 10123, 10127, 8811);
 script_xref(name:"IAVA", value:"2004-A-0005");
 script_xref(name:"OSVDB", value:"2670");
 script_xref(name:"OSVDB", value:"5245");
 script_xref(name:"OSVDB", value:"5246");
 script_xref(name:"OSVDB", value:"5247");

 script_name(english:"MS04-012: Cumulative Update for Microsoft RPC/DCOM (828741) (uncredentialed check)");
 script_summary(english:"Checks for MS04-012");

 script_set_attribute(
  attribute:"synopsis",
  value:"Arbitrary code can be executed on the remote host."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host has multiple bugs in its RPC/DCOM implementation\n",
   "(828741).\n",
   "\n",
   "An attacker may exploit one of these flaws to execute arbitrary code\n",
   "on the remote system."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for Windows NT, 2000, XP and\n",
   "2003 :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms04-012.mspx"
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_nativelanman.nasl");
 script_require_keys("Host/OS/smb");
 script_require_ports(135, 139, 445);
 exit(0);
}

#

include ('smb_func.inc');

function SCMActivatorGetClassObject (socket, type)
{
 local_var data, ret, resp, code;

 data =
	# struct 1
	raw_word(w:0) +
	raw_word(w:0) +
	raw_dword(d:0) +
	raw_dword(d:0) +
	raw_dword(d:0) +
	raw_word(w:0) +
	raw_word(w:0) +
	raw_dword(d:0) + raw_dword(d:0) +
	raw_dword(d:0) +

	# struct 2
	raw_dword(d:0) +
	raw_dword(d:0) +

	# struct4
	raw_dword(d:0x20000) +
	raw_dword(d:4) +
	raw_dword(d:4) +
	raw_dword(d:0);
	
 ret = dce_rpc_request (code:0x03, data:data);
 send (socket:socket, data:ret);
 resp = recv (socket:socket, length:4096);
 if (isnull(resp))
   return 0;

 if (strlen(resp) < 32 || ord(resp[2]) != 3)
   return 0;

 # 0x80010110 -> bad dcom header. Path should check it is a local call first and return ACCESS_DENIED
 code = get_dword (blob:resp, pos:24);
 if (code == 0x80010110)
   return 1;

 return 0;
}

 
os = get_kb_item("Host/OS/smb");
if ( "Windows" >!< os ) exit (0);


port = 135;

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp (port);
if (!soc) exit (0);

ret = dce_rpc_bind(cid:session_get_cid(), uuid:"00000136-0000-0000-c000-000000000046", vers:0);
send (socket:soc, data:ret);
resp = recv (socket:soc, length:4096);

if (!resp)
{
 close (soc);
 exit (0); 
}

ret = dce_rpc_parse_bind_ack (data:resp);
if (isnull (ret) || (ret != 0))
{
 close (soc);
 exit (0);
}


ret = SCMActivatorGetClassObject (socket:soc);
if (ret == 1)
  security_hole(port);
