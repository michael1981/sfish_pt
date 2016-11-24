#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(34413);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2008-3479");
 script_bugtraq_id(31637);
 script_xref(name:"OSVDB", value:"49060");

 script_name(english:"MS08-065: Microsoft Windows Message Queuing Service RPC Request Handling Remote Code Execution (951071) (uncredentialed check)");
 script_summary(english:"Determines if hotfix 951071 has been installed");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"Arbitrary code can be executed on the remote host."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote version of Windows is affected by a vulnerability in its\n",
   "Microsoft Message Queuing Service (MSMQ).\n",
   "\n",
   "An attacker may exploit this flaw to execute arbitrary code on the\n",
   "remote host with SYSTEM privileges."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for Windows 2000 :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms08-065.mspx"
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
 script_dependencies("smb_nativelanman.nasl");
 script_require_keys("Host/OS/smb");
 script_require_ports(2103);
 exit(0);
}

#

include ('smb_func.inc');
 
os = get_kb_item("Host/OS/smb");
if ( "Windows 5.0" >!< os ) exit (0);

port = 2103;
if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp (port);
if (!soc) exit (0);

ret = dce_rpc_bind(cid:session_get_cid(), uuid:"fdb3a030-065f-11d1-bb9b-00a024ea5525", vers:1);
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


session_set_unicode(unicode:1);

data = raw_dword(d:4);

ret = dce_rpc_request (code:0x1C, data:data);
send (socket:soc, data:ret);
resp = recv (socket:soc, length:4096);

close (soc);

resp = dce_rpc_parse_response (data:resp);
if (strlen(resp) <8)
  exit (0);

val = get_dword (blob:resp, pos:strlen(resp)-4);
if (val != 0) exit(0);

ref = get_dword(blob:resp, pos:0);
if (ref == 0) exit(0);

len = get_dword(blob:resp, pos:4);

s = get_string2 (blob:resp, pos:0x10, len:len*2);
if (egrep(pattern:"^[0-9]+,[0-9]+,[0-9]+$", string:s))
{
 v = split(s, sep:",",keep:FALSE);
 if ( (int(v[0]) < 2) ||
      (int(v[0]) == 2) && (int(v[1]) == 0) && (int(v[2]) < 807) )
   security_hole(port);
}
