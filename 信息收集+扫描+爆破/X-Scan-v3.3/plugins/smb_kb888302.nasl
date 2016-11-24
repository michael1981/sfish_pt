#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(16337);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-2005-0051");
 script_bugtraq_id(12486);
 script_xref(name:"OSVDB", value:"13596");

 script_name(english:"MS05-007: Vulnerability in Windows Could Allow Information Disclosure (888302) (uncredentialed check)");
 script_summary(english:"Determines if hotfix 888302 has been installed");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "System information about the remote host can be obtained by an\n",
   "anonymous user."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote version of Windows contains a flaw that may allow an\n",
   "attacker to cause it to disclose information over the use of a named\n",
   "pipe through a NULL session.\n",
   "\n",
   "An attacker may exploit this flaw to gain more knowledge about the\n",
   "remote host."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for Windows XP :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms05-007.mspx"
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_nativelanman.nasl");
 script_require_ports(139,445);
 exit(0);
}

#

include ("smb_func.inc");

os = get_kb_item ("Host/OS/smb") ;

# 'Officially', only XP is affected. 
if ( ! os || "Windows 5.1" >!< os ) exit(0);


name = kb_smb_name();
if(!name)exit(0);

port = int(get_kb_item("SMB/transport"));
if (!port) port = 445;

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init (socket:soc, hostname:name);
NetUseAdd (share:"IPC$");

if ( NetSessionEnum(level:SESSION_INFO_10) )
  security_warning(port);

NetUseDel ();

