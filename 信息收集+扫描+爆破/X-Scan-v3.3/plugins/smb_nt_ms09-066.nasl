#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42440);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-1928");
  script_bugtraq_id(36918);
  script_xref(name:"OSVDB", value:"59856");

  script_name(english:"MS09-066: Vulnerability in Active Directory Could Allow Denial of Service (973309)");
  script_summary(english:"Checks file version of Ntdsa.dll / Ntdsai.dll / Adamdsa.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The installed version of Active Directory is prone to a denial of
service attack."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The installed version of Microsoft Active Directory / Active
Directory Application Mode / Active Directory Lightweight Directory
Service has a buffer overflow vulnerability.  By sending specially
crafted LDAP or LDAPS requests, a remote attacker may be able to
exhaust stack space and cause the affected host to stop responding
until it is restarted."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003, 
and 2008 :

http://www.microsoft.com/technet/security/Bulletin/MS09-066.mspx"
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/11/10"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/11/10"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/11/10"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");
if (!get_kb_item("SMB/WindowsVersion")) exit(1, "The 'SMB/WindowsVersion' KB item is missing.");

if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:3) <= 0) exit(0, "The host is not affected based on its version / service pack.");


# Determine if Active Directory is enabled.
ADAM_Enabled = FALSE;
LDS_Enabled  = FALSE;
NTDS_Enabled = FALSE;

name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if (!get_port_state(port)) exit(1, "Port "+port+" is not open.");

soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open socket to port "+port+".");

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) 
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) 
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

key = "SYSTEM\CurrentControlSet\Services\NTDS\Parameters";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  NTDS_Enabled = TRUE;
  RegCloseKey(handle:key_h);
}

key = "SYSTEM\CurrentControlSet\Services\DirectoryServices\Performance";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  LDS_Enabled = TRUE;
  RegCloseKey(handle:key_h);
}

key = "SYSTEM\CurrentControlSet\Services\ADAM";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  ADAM_Enabled = TRUE;
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel();

if (!NTDS_Enabled && !LDS_Enabled && !ADAM_Enabled) 
  exit(0, "The host is not affected since none of the affected Active Directory products are installed.");

if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

# Check the file version.
if (
  # Windows 2008
  (
    (NTDS_Enabled || LDS_Enabled) && 
    (
      hotfix_is_vulnerable(os:"6.0", sp:2, file:"Ntdsai.dll",   version:"6.0.6002.22162", min_version:"6.0.6002.20000", dir:"\system32") ||
      hotfix_is_vulnerable(os:"6.0", sp:2, file:"Ntdsai.dll",   version:"6.0.6002.18058", min_version:"6.0.6002.18000", dir:"\system32") ||
      hotfix_is_vulnerable(os:"6.0", sp:1, file:"Ntdsai.dll",   version:"6.0.6001.22461", min_version:"6.0.6001.20000", dir:"\system32") ||
      hotfix_is_vulnerable(os:"6.0", sp:1, file:"Ntdsai.dll",   version:"6.0.6001.18281", min_version:"6.0.6001.18000", dir:"\system32")
    )
  ) ||

  # Windows 2003
  (NTDS_Enabled && hotfix_is_vulnerable(os:"5.2", sp:2, file:"ntdsa.dll",   version:"5.2.3790.4568", dir:"\system32")) ||
  (ADAM_Enabled && hotfix_is_vulnerable(os:"5.2", sp:2, file:"adamdsa.dll", version:"1.1.3790.4569", dir:"\ADAM")) ||

  # Windows XP
  (ADAM_Enabled && hotfix_is_vulnerable(os:"5.1",       file:"adamdsa.dll", version:"1.1.3790.4569", dir:"\ADAM")) ||

  # Windows 2000
  (NTDS_Enabled && hotfix_is_vulnerable(os:"5.0",       file:"ntdsa.dll",   version:"5.0.2195.7313", dir:"\system32"))
)
{
  set_kb_item(name:"SMB/Missing/MS09-066", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end(); 
  exit(0);
}
else
{
  hotfix_check_fversion_end(); 
  exit(0, "The host is not affected.");
}
