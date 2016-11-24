#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39347);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-1123", "CVE-2009-1124", "CVE-2009-1125", "CVE-2009-1126");
  script_bugtraq_id(35120, 35121, 35238, 35240);
  script_xref(name:"OSVDB", value:"54940");
  script_xref(name:"OSVDB", value:"54941");
  script_xref(name:"OSVDB", value:"54942");
  script_xref(name:"OSVDB", value:"54943");

  script_name(english:"MS09-025: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (968537)");
  script_summary(english:"Checks file version of Win32k.sys");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Windows kernel is affected by local privilege escalation\n",
      "vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host contains a version of the Windows kernel that is\n",
      "affected by multiple vulnerabilities :\n",
      "\n",
      "  - A failure of the Windows kernel to properly validate \n",
      "    changes in certain kernel objects allows a local user\n",
      "    to run arbitrary code in kernel mode. (CVE-2009-1123)\n",
      "\n",
      "  - Insufficient validation of certain pointers passed from\n",
      "    user mode allows a local user to run arbitrary code in \n",
      "    kernel mode. (CVE-2009-1124)\n",
      "\n",
      "  - A failure to properly validate an argument passed to a \n",
      "    Windows kernel system call allows a local user to run \n",
      "    arbitrary code in kernel mode. (CVE-2009-1125)\n",
      "\n",
      "  - Improper validation of input passed from user mode to \n",
      "    the kernel when editing a specific desktop parameter\n",
      "    allows a local user to run arbitrary code in kernel \n",
      "    mode. (CVE-2009-1126)"
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Windows 2000, XP, 2003,\n",
      "Vista and 2008 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-025.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C"
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


if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:3) <= 0) exit(0);

if (is_accessible_share())
{
  if (
    # Vista / Windows Server 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.22119", min_version:"6.0.6002.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.18023",                               dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Win32k.sys", version:"6.0.6001.22416", min_version:"6.0.6001.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Win32k.sys", version:"6.0.6001.18246",                               dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Win32k.sys", version:"6.0.6000.21044", min_version:"6.0.6000.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Win32k.sys", version:"6.0.6000.16849",                               dir:"\system32") ||

    # Windows 2003
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Win32k.sys", version:"5.2.3790.4497", dir:"\system32") ||

    # Windows XP
    hotfix_is_vulnerable(os:"5.1", sp:3, file:"Win32k.sys", version:"5.1.2600.5796", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.1", sp:2, file:"Win32k.sys", version:"5.1.2600.3556", dir:"\system32") ||

    # Windows 2000
    hotfix_is_vulnerable(os:"5.0", file:"Win32k.sys", version:"5.0.2195.7279", dir:"\system32")
  )
  {
    set_kb_item(name:"SMB/Missing/MS09-025", value:TRUE);
    hotfix_security_hole();
  }

  hotfix_check_fversion_end();
}
