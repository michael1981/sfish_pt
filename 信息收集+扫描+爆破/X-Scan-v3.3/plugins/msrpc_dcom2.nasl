#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if(description)
{
 script_id(11835);
 script_version ("$Revision: 1.54 $");
 
 script_cve_id("CVE-2003-0715", "CVE-2003-0528", "CVE-2003-0605");
 script_bugtraq_id(8458, 8460);
 script_xref(name:"OSVDB", value:"2535");
 script_xref(name:"OSVDB", value:"11460");
 script_xref(name:"OSVDB", value:"11797");
 script_xref(name:"IAVA", value:"2003-A-0012");

 script_name(english:"MS03-039: Microsoft RPC Interface Buffer Overrun (824146) (uncredentialed check)");
 script_summary(english:"Checks if the remote host has a patched RPC interface (KB824146)");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"Arbitrary code can be executed on the remote host."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host is running a version of Windows that has a flaw in its\n",
   "RPC interface, which may allow an attacker to execute arbitrary code\n",
   "and gain SYSTEM privileges.\n",
   "\n",
   "An attacker or a worm could use it to gain the control of this host.\n",
   "\n",
   "Note that this is NOT the same bug as the one described in MS03-026,\n",
   "which fixes the flaw exploited by the 'MSBlast' (or LoveSan) worm.\n"
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:"http://www.microsoft.com/technet/security/bulletin/MS03-039.mspx"
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_require_ports(135, 139, 445);
 script_dependencies("smb_nativelanman.nasl");
 exit(0);
}

#

include ('smb_func.inc');

function RemoteGetClassObject ()
{
 local_var fid, data, rep, ret;

 fid = bind_pipe (pipe:"\epmapper", uuid:"000001a0-0000-0000-c000-000000000046", vers:0);
 if (isnull (fid))
   return 0;

 data = raw_word (w:5) +
        raw_word (w:6) +
        raw_dword (d:1) +
        raw_dword (d:0) +
        encode_uuid (uuid:"54454e41-424c-454e-4554-574f524b5345") +
	raw_dword (d:0) +
        raw_dword (d:0x20000) +
	raw_dword (d:12) +
        raw_dword (d:12) +
	crap (data:"A", length:12) +
        raw_dword (d:0);


 data = dce_rpc_pipe_request (fid:fid, code:0x03, data:data);
 if (!data)
   return 0;

 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen(rep) != 16))
   return 0;

 ret = get_dword (blob:rep, pos:strlen(rep)-4);
 if ((ret == 0x8001011d) || (ret == 0x80070057) || (ret == 0x80070005))
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
 set_kb_item (name:"SMB/KB824146_launched", value:TRUE);

 ret = RemoteGetClassObject();
 if (ret == 1)
   security_hole(port:port);
 else
   set_kb_item(name:"SMB/KB824146", value:TRUE);

 NetUseDel();
}
