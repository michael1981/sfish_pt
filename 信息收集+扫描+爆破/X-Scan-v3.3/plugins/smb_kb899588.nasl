#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(19408);
 script_version("$Revision: 1.22 $");

 script_cve_id("CVE-2005-1983");
 script_bugtraq_id(14513);
 script_xref(name:"IAVA", value:"2005-A-0025");
 script_xref(name:"OSVDB", value:"18605");

 script_name(english:"MS05-039: Vulnerability in Plug and Play Service Could Allow Remote Code Execution (899588) (uncredentialed check)");
 script_summary(english:"Determines the presence of update 899588 (remote check)");

 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "Arbitrary code can be executed on the remote host due to a flaw in the\n",
   "Plug-And-Play service."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote version of Windows contains a flaw in the function\n",
   "'PNP_QueryResConfList()' in the Plug and Play service that may allow\n",
   "an attacker to execute arbitrary code on the remote host with SYSTEM\n",
   "privileges.\n",
   "\n",
   "A series of worms (Zotob) are known to exploit this vulnerability in\n",
   "the wild."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for Windows 2000, XP and \n",
   "2003 :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms05-039.mspx"
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

function PNP_QueryResConfList (pipe)
{
 local_var fid, data, rep, ret;

 fid = bind_pipe (pipe:pipe, uuid:"8d9f4e40-a03d-11ce-8f69-08003e30051b", vers:1);
 if (isnull (fid))
   return 0;

 data = class_name (name:"tns") +
	raw_dword (d:0) +
	raw_dword (d:0) +
	raw_dword (d:0) +
	raw_dword (d:0) +
	raw_dword (d:0);

 data = dce_rpc_pipe_request (fid:fid, code:0x36, data:data);
 if (!data)
   return 0;

 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen(rep) != 8))
   return 0;

 ret = get_dword (blob:rep, pos:4);
 if (ret != 0x05)
   return 0;

 return 1;
}

os = get_kb_item ("Host/OS/smb") ;
if ( ("Windows 5.2" >< os) || ("Windows 4.0" >< os) ) exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 445;

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

name	= kb_smb_name();

session_init(socket:soc, hostname:name);

if ( ( "Windows 5.1" >< os ) && get_kb_item("SMB/any_login") )
{
 rpipe = "\svcctl";
 rand_lg = string ( "nessus", rand(), rand(), rand() ); 
 rand_pw = string ( "nessus", rand(), rand(), rand() );
 r = NetUseAdd(login:rand_lg, password:rand_pw, share:"IPC$");
}
else
{
 rpipe = "\srvsvc";
 r = NetUseAdd(share:"IPC$");
}
if ( r == 1 )
{
 ret = PNP_QueryResConfList(pipe:rpipe);
 if (ret == 1)
   security_hole(port:port);

 NetUseDel();
}
