#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(20006);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-2005-1985");
 script_bugtraq_id(15066);
 script_xref(name:"OSVDB", value:"19922");

 script_name(english:"MS05-046: Vulnerability in the Client Service for NetWare Could Allow Remote Code Execution (899589) (uncredentialed check)");
 script_summary(english:"Determines the presence of update 899589 (remote check)");

 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "A flaw in the client service for NetWare may allow an attacker to\n",
   "execute arbitrary code on the remote host."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host contains a version of the Client Service for NetWare\n",
   "that is vulnerable to a buffer overflow.\n",
   "\n",
   "An attacker may exploit this flaw by connecting to the NetWare RPC\n",
   "service (possibly over IP) and triggering the overflow by sending a\n",
   "malformed RPC request."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for Windows 2000, XP and\n",
   "2003 :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms05-046.mspx"
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_nativelanman.nasl","smb_login.nasl");
 script_require_keys("Host/OS/smb");
 script_require_ports(139,445);
 exit(0);
}

#

include ('smb_func.inc');

global_var rpipe;

function RPC_Request (pipe)
{
 local_var fid, data, rep, ret;

 fid = bind_pipe (pipe:"\browser", uuid:"e67ab081-9844-3521-9d32-834f038001c0", vers:1);
 if (isnull (fid))
   return 0;

 data = class_parameter (ref_id:0x20000, name:"tns1") +
	class_parameter (ref_id:0x20004, name:"tns2") +
	raw_dword (d:0);

 session_set_timeout (timeout:20);

 data = dce_rpc_pipe_request (fid:fid, code:0x2d, data:data);
 if (!data)
   return 0;

 rep = dce_rpc_parse_response (fid:fid, data:data);

 if (!rep || (strlen(rep) != 8))
   return 0;

 ret = get_dword (blob:rep, pos:4);
 if ((ret == ERROR_INVALID_PARAMETER) || (ret == ERROR_ACCESS_DENIED))
   return 0;

 return 1;
}

os = get_kb_item ("Host/OS/smb") ;
if ("Windows" >!< os) exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 445;

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

name	= kb_smb_name();

session_init(socket:soc, hostname:name);

r = NetUseAdd(share:"IPC$");
if ( r == 1 )
{
 ret = RPC_Request();
 if (ret == 1)
   security_hole(port:port);

 NetUseDel();
}
