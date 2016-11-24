#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);

include("compat.inc");

if(description)
{
 script_id(34477);
 script_version("$Revision: 1.22 $");

 script_cve_id("CVE-2008-4250");
 script_bugtraq_id(31874);
 script_xref(name:"OSVDB", value:"49243");

 script_name(english:"MS08-067: Microsoft Windows Server Service Crafted RPC Request Handling Remote Code Execution (958644) (uncredentialed check)");
 script_summary(english:"Determines the presence of update 958644");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "Arbitrary code can be executed on the remote host due to a flaw in the\n",
   "'Server' service."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host is vulnerable to a buffer overrun in the 'Server'\n",
   "service that may allow an attacker to execute arbitrary code on the\n",
   "remote host with the 'System' privileges."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for Windows 2000, XP, 2003,\n",
   "Vista and 2008 :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms08-067.mspx"
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_nativelanman.nasl","smb_login.nasl");
 if ( NASL_LEVEL >= 3200 )
  script_dependencies("smb_kb958644_ips.nbin");
 script_require_keys("Host/OS/smb");
 script_require_ports(139, 445);
 exit(0);
}

#

include ('smb_func.inc');

if ( get_kb_item("SMB/KB958644/34821/Vulnerable") ) security_hole(0);
if ( get_kb_item("SMB/KB958644/34821") ) exit(0);

function  NetPathCanonicalize ()
{
 local_var data, data2, fid, fid2, rep, ret;

 fid = bind_pipe (pipe:"\browser", uuid:"4b324fc8-1670-01d3-1278-5a47bf6ee188", vers:3);
 if (isnull (fid))
   return 0;

 fid2 = bind_pipe (pipe:"\browser", uuid:"6bffd098-a112-3610-9833-46c3f87e345a", vers:1);
 if (isnull (fid2))
   return 0;

 data2 = class_parameter (name:"", ref_id:0x20000) +
        class_name (name:crap(data:"\A", length:0x100)) +
	raw_dword (d:0) ;
 
 data = class_parameter (name:"", ref_id:0x20000) +
        class_name (name:"\" + crap(data:"A", length:0x23) + "\..\nessus") +
	class_name (name:"\nessus") + 
	raw_dword (d:1) +
	raw_dword (d:0) ;
 
 data2 = dce_rpc_pipe_request (fid:fid2, code:0x0A, data:data2);
 if (!data2)
   return 0;

 data = dce_rpc_pipe_request (fid:fid, code:0x20, data:data);
 if (!data)
   return 0;


 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen(rep) != 4))
   return 0;

 ret = get_dword (blob:rep, pos:strlen(rep)-4);
 if (ret == 0)
   return 1;

 return 0;
}

os = get_kb_item ("Host/OS/smb") ;
if ("Windows" >!< os) exit(0);

name	= kb_smb_name();
port	= kb_smb_transport();

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init(socket:soc, hostname:name);

r = NetUseAdd(share:"IPC$");
if ( r == 1 )
{
 ret = NetPathCanonicalize ();
 if (ret == 1)
   security_hole(port:port);
 else 
   set_kb_item(name:"SMB/KB958644/34477", value:TRUE);
 NetUseDel();
}
