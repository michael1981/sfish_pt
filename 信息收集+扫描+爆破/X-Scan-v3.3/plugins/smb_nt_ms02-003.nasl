#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11309);
 script_version("$Revision: 1.19 $");
 
 script_cve_id("CVE-2002-0049");
 script_bugtraq_id(4053);
 script_xref(name:"OSVDB", value:"2042");
 
 script_name(english:"MS02-003: WinReg Remote Registry Key Manipulation (316056)");
 
 script_set_attribute(attribute:"synopsis", value:
"Local users can elevate their privileges." );
 script_set_attribute(attribute:"description", value:
"The key HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg 
is writeable by non-administrators.

The installation software of Microsoft Exchange sets this key to
a world-writeable mode.

Local users may use this misconfiguration to escalate their privileges on 
this host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for the Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms02-003.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Determines the permissions for the winreg key");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_full_access.nasl",
 		     "smb_reg_service_pack.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");

access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 139;

name	= kb_smb_name(); 	if(!name)exit(0);
login	= kb_smb_login(); 
pass	= kb_smb_password(); 	
domain  = kb_smb_domain(); 	
port	= kb_smb_transport();

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(0);
}

key = "SYSTEM\CurrentControlSet\Control\SecurePipeServers\WinReg";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY); 
if(!isnull(key_h))
{
 rep = RegGetKeySecurity (handle:key_h, type: DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION);
 if(!isnull(rep) && registry_key_writeable_by_non_admin(security_descriptor:rep))
 {
 {
 set_kb_item(name:"SMB/Missing/MS02-003", value:TRUE);
 security_hole(port);
 }
 }
 RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);
NetUseDel();
