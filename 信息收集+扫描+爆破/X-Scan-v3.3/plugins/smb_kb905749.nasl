#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);
include("compat.inc");

if(description)
{
 script_id(21193);
 script_version("$Revision: 1.10 $");

 script_cve_id("CVE-2005-2120");
 script_bugtraq_id(15065);
 script_xref(name:"OSVDB", value:"18830");

 script_name(english:"MS05-047: Plug and Play Remote Code Execution and Local Privilege Elevation (905749) (uncredentialed check)");
 script_summary(english:"Determines the presence of update 905749");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "A flaw in the Plug and Play service may allow an authenticated\n",
   "attacker to execute arbitrary code on the remote host and therefore\n",
   "elevate his privileges."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host contain a version of the Plug and Play service that\n",
   "contains a vulnerability in the way it handles user-supplied data.\n",
   "\n",
   "An authenticated attacker may exploit this flaw by sending a malformed\n",
   "RPC request to the remote service and execute code with SYSTEM\n",
   "privileges.\n",
   "\n",
   "Note that authentication is not required against Windows 2000 if the\n",
   "MS05-039 patch is missing."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for Windows 2000 and XP :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms05-047.mspx"
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
 script_dependencies("smb_nativelanman.nasl","smb_login.nasl");
 script_require_keys("Host/OS/smb");
 script_require_ports(139,445);
 exit(0);
}

#

include ('smb_func.inc');

function  PNP_ValidateDeviceInstance ()
{
 local_var fid, data, rep, ret;

 fid = bind_pipe (pipe:"\browser", uuid:"8d9f4e40-a03d-11ce-8f69-08003e30051b", vers:1);
 if (isnull (fid))
   return 0;

 # MS05-047 on 2000 checks that the character is between 0x20 and 0x7F
 # if it is not the case the return code is 5
 data = 
	class_name(name:'HTREE\\ROOT'+raw_string(0x1f)+'\\0') +
	raw_dword(d:3);

 data = dce_rpc_pipe_request (fid:fid, code:0x06, data:data);
 if (!data)
   return 0;

 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen(rep) != 4))
   return 0;

 # 0x33 -> Access Denied
 ret = get_dword (blob:rep, pos:0);
 if ((ret != 0x33) && (ret != 0x05))
   return 1;


 return 0;
}

os = get_kb_item ("Host/OS/smb") ;
if ("Windows 5.0" >!< os) exit(0);

name	= kb_smb_name();
port	= kb_smb_transport();
login   = kb_smb_login();
pass    = kb_smb_password();


if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init(socket:soc, hostname:name);

r = NetUseAdd(login:login, password:pass, share:"IPC$");
if ( r == 1 )
{
 ret = PNP_ValidateDeviceInstance ();
 if (ret == 1)
   security_hole(port:port);

 NetUseDel();
}
