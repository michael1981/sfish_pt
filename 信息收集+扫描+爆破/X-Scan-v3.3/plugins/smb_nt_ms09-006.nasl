#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35822);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-0081", "CVE-2009-0082", "CVE-2009-0083");
  script_bugtraq_id(34012, 34025, 34027);
  script_xref(name:"OSVDB", value:"52522");
  script_xref(name:"OSVDB", value:"52523");
  script_xref(name:"OSVDB", value:"52524");

  script_name(english: "MS09-006: Vulnerabilities in Windows Kernel Could Allow Remote Code Execution (958690)");
  script_summary(english:"Determines the presence of update 958690");

  script_set_attribute(
    attribute:"synopsis",
    value:"It is possible to execute arbitrary code on the remote host."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host contains a version of the Windows kernel that is\n",
      "affected by vulnerabilities :\n",
      "\n",
      "  - A remote code execution vulnerability exists due to\n",
      "    improper validation of input passed from user mode\n",
      "    through the kernel component of GDI. Successful\n",
      "    exploitation requires that a user on the affected host\n",
      "    view a specially crafted EMF or WMF image file, perhaps\n",
      "    by being tricked into visiting a malicious web site,\n",
      "    and could lead to a complete system compromise.\n",
      "    (CVE-2009-0081)\n",
      "\n",
      "  - A local privilege escalation vulnerability exists due to\n",
      "    the way the kernel validates handles. (CVE-2009-0082)\n",
      "\n",
      "  - A local privilege escalation vulnerability exists due to\n",
      "    improper handling of a specially crafted invalid pointer.\n",
      "    (CVE-2009-0083)"
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Windows 2000, XP, 2003,\n",
      "Vista and 2008 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-006.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
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


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:2) <= 0) exit(0);

if (is_accessible_share())
{
  if (
    # Windows Vista and Windows Server 2008
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Win32k.sys", version:"6.0.6001.22372", min_version:"6.0.6001.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Win32k.sys", version:"6.0.6001.18211", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Win32k.sys", version:"6.0.6000.21006", min_version:"6.0.6000.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Win32k.sys", version:"6.0.6000.16816", dir:"\system32") ||

    # Windows 2003
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Win32k.sys", version:"5.2.3790.4456", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.2", sp:1, file:"Win32k.sys", version:"5.2.3790.3291", dir:"\system32") ||

    # Windows XP
    hotfix_is_vulnerable(os:"5.1", sp:3, file:"Win32k.sys", version:"5.1.2600.5756", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.1", sp:2, file:"Win32k.sys", version:"5.1.2600.3521", dir:"\system32") ||

    # Windows 2000
    hotfix_is_vulnerable(os:"5.0", file:"Win32k.sys", version:"5.0.2195.7251", dir:"\system32")
  ) {
 set_kb_item(name:"SMB/Missing/MS09-006", value:TRUE);
 hotfix_security_hole();
 }
 
  hotfix_check_fversion_end();
}
