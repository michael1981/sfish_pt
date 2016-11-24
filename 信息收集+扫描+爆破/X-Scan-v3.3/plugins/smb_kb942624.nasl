#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(29855);
 script_version("$Revision: 1.9 $");

 script_cve_id("CVE-2007-5351");
 script_bugtraq_id(26777);
 script_xref(name:"OSVDB", value:"39125");

 script_name(english:"MS07-063: Vulnerability in SMBv2 Could Allow Remote Code Execution (942624) (uncredentialed check)");
 script_summary(english:"Determines the presence of update 942624");

 script_set_attribute(
  attribute:"synopsis",
  value:"It is possible to execute arbitrary code on the remote host."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote version of Windows contains a version of SMBv2 (Server\n",
   "Message Block) protocol that is affected by several vulnerabilities. \n",
   "\n",
   "An attacker may exploit these flaws to elevate his privileges and gain\n",
   "control of the remote host."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for Windows Vista :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms07-063.mspx"
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
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");

os = get_kb_item ("Host/OS/smb") ;
if ( ! os || "Windows 6.0" >!< os ) exit(0);

port = kb_smb_transport();
name = kb_smb_name();

if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

session_init (socket:soc,hostname:name, smb2:FALSE);


# We redefine the list of supported protocols by replacing smbv2.002 by smbv2.001
supported_protocol--;
protocol[supported_protocol++] = "SMB 2.001";
protocol[supported_protocol++] = "SMB 2.002";  # will be removed by negotiate call


ret = smb_negotiate_protocol (extended:FALSE);
if (!ret)
  exit(0);

# Some checks in the header first
header = get_smb_header (smbblob:ret);
if (!header || strlen(header) < 4)
  exit(0);

head = substr(header, 0, 3);

# patched version no longer works with SMB 2.001 (but SMB 2.002)
if (head == '\xfeSMB')
  security_hole(port);
