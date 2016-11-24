#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(11528);
 script_version ("$Revision: 1.16 $");

 script_cve_id("CVE-2003-0111");
 script_xref(name:"OSVDB", value:"2969");
 
 name["english"] = "MS03-011: Flaw in Microsoft VM (816093)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the VM." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a Microsoft VM machine which has a bug in
its bytecode verifier that may allow a remote attacker to execute
arbitrary code on this host with the privileges of the user running
the VM. 

To exploit this vulnerability, an attacker would need to send a
malformed applet to a user on this host and have him execute it.  The
malicious applet would then be able to execute code outside the
sandbox of the VM." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for the Windows VM :

http://www.microsoft.com/technet/security/bulletin/ms03-011.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Checks for the version of the remote VM";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys( "SMB/WindowsVersion", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");

rootfile = hotfix_get_systemroot();
if ( ! rootfile ) exit(1);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\Jview.exe", string:rootfile);



port    =  kb_smb_transport();
if(!get_port_state(port))exit(1);
soc = open_sock_tcp(port);
if(!soc)exit(1);

session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:kb_smb_login(), password:kb_smb_password(), domain:kb_smb_domain(), share:share);
if ( r != 1 ) exit(1);

handle =  CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if ( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) )
 {
  # Fixed in 5.0.3810.0 or newer
  if ( v[0] < 5 || (v[0] == 5 && v[1] == 0 && v[2] < 3810 ) )
	 {
 set_kb_item(name:"SMB/Missing/MS03-011", value:TRUE);
 security_hole( port );
 }
  else
	set_kb_item(name:"KB816093", value:TRUE);
 } 
 else 
 {
  NetUseDel();
  exit(1);
 }
}

NetUseDel();
