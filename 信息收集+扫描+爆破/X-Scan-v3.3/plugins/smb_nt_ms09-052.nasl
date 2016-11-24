#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42108);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2009-2527");
  script_bugtraq_id(36644);
  script_xref(name:"OSVDB", value:"58843");

  script_name(english:"MS09-052: Vulnerability in Windows Media Player Could Allow Remote Code Execution (974112)");
  script_summary(english:"Checks version of strmdll.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "Arbitrary code can be executed on the remote host through Windows\n",
      "Media Player."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host contains a version of Windows Media Player that is\n",
      "affected by a heap-based buffer overflow vulnerability.\n",
      "\n",
      "If an attacker can trick a user on the affected host into opening a\n",
      "specially crafted ASF (Advanced Systems Format) file, he may be able\n",
      "to leverage this issue to run arbitrary code on the host subject to\n",
      "the user's privileges."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Windows 2000, XP, and\n",
      "2003 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-052.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/10/13"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/10/13"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/10/13"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsMediaPlayer", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}



include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if (!get_kb_item("SMB/WindowsVersion")) exit(1, "The 'SMB/WindowsVersion' KB item is missing.");
if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");

if (hotfix_check_sp(win2k:6, xp:4, win2003:3) <= 0) exit(0, "Host is not affected based on its version / service pack.");
if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

version = get_kb_item("SMB/WindowsMediaPlayer");
if (!version) exit(1, "The 'SMB/WindowsMediaPlayer' KB item is missing.");


if (
  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"strmdll.dll", version:"4.1.0.3938", dir:"\SysWOW64") ||
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"strmdll.dll", version:"4.1.0.3938", dir:"\System32") ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"strmdll.dll", version:"4.1.0.3938", dir:"\System32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"strmdll.dll", version:"4.1.0.3938", dir:"\SysWOW64") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"strmdll.dll", version:"4.1.0.3938", dir:"\System32") ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0",                   file:"strmdll.dll", version:"4.1.0.3938", dir:"\System32")
)
{
  set_kb_item(name:"SMB/Missing/MS09-052", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end(); 
  exit(0);
}
else
{
  hotfix_check_fversion_end(); 
  exit(0, "The host is not affected.");
}
