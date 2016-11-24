#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(31037);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2008-0088");
 script_bugtraq_id(27638);

 name["english"] = "MS08-003: Vulnerability in Active Directory Could Allow Denial of Service (946538)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash Active Directory on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote version of Active Directory contains a flaw in the LDAP
request handler code which may allow an attacker to crash the remote
Active Directory server." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, Windows XP
and Windows 2003 :

http://www.microsoft.com/technet/security/bulletin/ms08-003.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 summary["english"] = "Determines the presence of update 946538";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
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

if ( hotfix_check_sp(win2003:3, win2k:6, xp:3) <= 0 ) exit(0);

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

RegCloseKey(handle:hklm);
NetUseDel();



if (is_accessible_share())
{
 if ( ( NTDS_Enabled && hotfix_is_vulnerable (os:"5.2", sp:1, file:"ntdsa.dll", version:"5.2.3790.3043", dir:"\system32")) ||
      ( NTDS_Enabled && hotfix_is_vulnerable (os:"5.2", sp:2, file:"ntdsa.dll", version:"5.2.3790.4188", dir:"\system32")) ||
      ( ADAM_Enabled && hotfix_is_vulnerable (os:"5.2", sp:1, file:"adamdsa.dll", version:"1.1.3790.3043", dir:"\ADAM")) ||
      ( ADAM_Enabled && hotfix_is_vulnerable (os:"5.2", sp:2, file:"adamdsa.dll", version:"1.1.3790.4188", dir:"\ADAM")) ||
      ( ADAM_Enabled && hotfix_is_vulnerable (os:"5.1", sp:2, file:"adamdsa.dll", version:"1.1.3790.4188", dir:"\ADAM")) ||
      ( NTDS_Enabled && hotfix_is_vulnerable (os:"5.0", file:"ntdsa.dll", version:"5.0.2195.7147", dir:"\system32")) )
 {
 set_kb_item(name:"SMB/Missing/MS08-003", value:TRUE);
 hotfix_security_warning();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
