#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(25690);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2007-3028", "CVE-2007-0040");
 script_bugtraq_id(24796, 24800);
 script_xref(name:"OSVDB", value:"35960");
 script_xref(name:"OSVDB", value:"35961");

 script_name(english: "MS07-039: Microsoft Windows Active Directory LDAP Service Remote Code Execution (926122)");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote version of Active Directory contains a flaw in the LDAP
request handler code which may allow an attacker to execute code
on the remote host.
On Windows 2000 an anonymous attacker can exploit this flaw by sending
a specially crafted LDAP packet.
On Windows 2003 valid credentials are needed to exploit it.

Additionally the Active Directory is vulnerable to a remote Denial of
Service Vulnerability." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000 and 2003:

http://www.microsoft.com/technet/security/bulletin/ms07-039.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Determines the presence of update 926122";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");

if ( hotfix_check_sp(win2003:3, win2k:6) <= 0 ) exit(0);

# Is ActiveDirectory Enabled ?
name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) 
{
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) 
{
  NetUseDel();
  exit(0);
}


key = "SYSTEM\CurrentControlSet\Services\NTDS\Parameters";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) NTDS_Enabled = TRUE;
else RegCloseKey(handle:key_h);


key = "SYSTEM\CurrentControlSet\Services\ADAM";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) ) ADAM_Enabled = TRUE;
else RegCloseKey(handle:key_h);

key = "SYSTEM\CurrentControlSet\Services\DirectoryServices\Performance";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) ) LDS_Enabled = TRUE;
else RegCloseKey(handle:key_h);

RegCloseKey(handle:hklm);
NetUseDel();

if ( !NTDS_Enabled && !LDS_Enabled && !ADAM_Enabled ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:1, file:"ntdsa.dll", version:"5.2.3790.2926", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"ntdsa.dll", version:"5.2.3790.4070", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"ntdsa.dll", version:"5.0.2195.7135", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS07-039", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}


