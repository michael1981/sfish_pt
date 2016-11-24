#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39340);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-1138", "CVE-2009-1139");
  script_bugtraq_id(35225, 35226);
  script_xref(name:"OSVDB", value:"54937");
  script_xref(name:"OSVDB", value:"54938");

  script_name(english:"MS09-018: Vulnerabilities in Active Directory Could Allow Remote Code Execution (971055)");
  script_summary(english:"Checks file version of Ntdsa.dll / Adamdsa.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "Arbitrary code can be executed on the remote host through Microsoft\n",
      "Active Directory."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The version of Microsoft Active Directory / Active Directory\n",
      "Application Mode installed on the remote host is affected by one or\n",
      "both of the following vulnerabilities :\n",
      "\n",
      "  - A flaw involving the way memory is freed when handling\n",
      "    specially crafted LDAP or LDAPS requests may enable a\n",
      "    remote attacker to execute arbitrary code on the remote\n",
      "    host with administrator privileges. Note that this is\n",
      "    only known to affect Active Directory on Microsoft\n",
      "    Windows 2000 Server Service Pack 4. (CVE-2009-1138)\n",
      "\n",
      "  - Improper memory management during execution of certain\n",
      "    types of LDAP or LDAPS requests may cause the affected\n",
      "    product to stop responding. (CVE-2009-1139)"
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Windows 2000, Windows XP\n",
      "and Windows 2003 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-018.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
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


if (hotfix_check_sp(win2k:6, xp:4, win2003:3) <= 0) exit(0);


# Determine if ActiveDirectory is enabled.
ADAM_Enabled = FALSE;
NTDS_Enabled = FALSE;

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

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) 
{
  NetUseDel();
  exit(0);
}

key = "SYSTEM\CurrentControlSet\Services\NTDS\Parameters";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  NTDS_Enabled = TRUE;
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

if (!NTDS_Enabled && !ADAM_Enabled) exit(0);


# Check the file version.
if (is_accessible_share())
{
  if (
    # Windows 2003
    (NTDS_Enabled && hotfix_is_vulnerable(os:"5.2", sp:2, file:"ntdsa.dll",   version:"5.2.3790.4501", dir:"\system32")) ||
    (ADAM_Enabled && hotfix_is_vulnerable(os:"5.2", sp:2, file:"adamdsa.dll", version:"1.1.3790.4503", dir:"\ADAM")) ||

    # Windows XP
    (ADAM_Enabled && hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"adamdsa.dll", version:"1.1.3790.4501", dir:"\ADAM")) ||
    (ADAM_Enabled && hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"adamdsa.dll", version:"1.1.3790.4503", dir:"\ADAM")) ||
    (ADAM_Enabled && hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"adamdsa.dll", version:"1.1.3790.4501", dir:"\ADAM")) ||

    # Windows 2000
    (NTDS_Enabled && hotfix_is_vulnerable(os:"5.0", file:"ntdsa.dll",   version:"5.0.2195.7292", dir:"\system32"))
  )
  {
    set_kb_item(name:"SMB/Missing/MS09-018", value:TRUE);
    hotfix_security_hole();
  }
  hotfix_check_fversion_end(); 
}
