#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40889);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-2519");
  script_bugtraq_id(36280);
  script_xref(name:"OSVDB", value:"57798");

  script_name(english:"MS09-046: Vulnerability in DHTML Editing Component ActiveX Control Could Allow Remote Code Execution (956844)");
  script_summary(english:"Checks version of triedit.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "Arbitrary code can be executed on the remote host through an\n",
      "ActiveX control."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote host is missing Security Update 956844.  The DHTML Editing\n",
      "Component ActiveX Control on the remote host has a remote code\n",
      "execution vulnerability.  A remote attacker could exploit this by\n",
      "tricking a user into viewing a specially crafted web page, resulting\n",
      "in the execution of arbitrary code."
    )
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Microsoft has released a set of patches for Windows 2000, XP,\n",
      "and 2003 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/bulletin/MS09-046.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/09/08"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/09/08"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/09/08"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if (!get_kb_item("SMB/WindowsVersion")) exit(1, "The 'SMB/WindowsVersion' KB item is missing.");
if (hotfix_check_sp(win2k:6, xp:4, win2003:3) <= 0) exit(0, "The host is not affected based on its version / service pack.");

# BEGIN - Gets the Program Files (x86) dir from the registry
if (!get_kb_item("SMB/Registry/Enumerated"))
  exit(1, "The registry wasn't enumerated.");

name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(1, "Error creating a socket on with dest port " + port);

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  prog_files_x64 = RegQueryValue(handle:key_h, item:"ProgramFilesDir (x86)");
  if (prog_files_x64) prog_files_x64 = prog_files_x64[1];

  RegCloseKey(handle:key_h);
}
else debug_print("Unable to get handle for HKLM\" + key);

RegCloseKey(handle:hklm);
NetUseDel();
# END - Gets the Program Files (x86) dir from the registry

prog_files = hotfix_get_programfilesdir();
if (!prog_files) exit(1, "Can't determine Program Files directory.");

if (prog_files_x64)
  dir_x64 = prog_files_x64 + "\Common Files\Microsoft Shared\Triedit";

dir = prog_files + "\Common Files\Microsoft Shared\Triedit";
ver = '6.1.0.9246';
ver_2k = '6.1.0.9235';

if (
  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"Triedit.dll", version:ver,   path:dir) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Triedit.dll", version:ver,   path:dir_x64) ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Triedit.dll", version:ver,   path:dir) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Triedit.dll", version:ver,   path:dir) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Triedit.dll", version:ver,   path:dir_x64) ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0", file:"Triedit.dll", version:ver_2k, path:dir)
)
{
  set_kb_item(name:"SMB/Missing/MS09-046", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected.");
}
