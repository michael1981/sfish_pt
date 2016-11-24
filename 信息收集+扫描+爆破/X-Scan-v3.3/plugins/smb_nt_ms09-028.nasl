#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39791);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-1537", "CVE-2009-1538", "CVE-2009-1539");
  script_bugtraq_id(35139, 35600, 35616);
  script_xref(name:"OSVDB", value:"54797");
  script_xref(name:"OSVDB", value:"55844");
  script_xref(name:"OSVDB", value:"55845");

  script_name(english:"MS09-028: Vulnerabilities in Microsoft DirectShow Could Allow Remote Code Execution (971633)");
  script_summary(english:"Checks version of Quartz.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "It is possible to execute arbitrary code on the remote Windows host\n",
      "using DirectX."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The DirectShow component included with the version of Microsoft\n",
      "DirectX installed on the remote host is affected by multiple\n",
      "vulnerabilities that may allow execution of arbitrary code when\n",
      "processing a specially crafted QuickTime media file."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for DirectX 7.0, 8.0 and 9.0 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-028.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/05/28"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/07/14"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/07/14"
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


if (!get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/DirectX/Version")) exit(0, "Host does not have DirectX installed.");

if (hotfix_check_sp(win2k:6, xp:4, win2003:3) <= 0) exit(0, "Host is not affected based on its version / service pack.");

if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");


if (
  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Quartz.dll", version:"6.5.3790.4523", dir:"\System32") ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Quartz.dll", version:"6.5.2600.5822", dir:"\System32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Quartz.dll", version:"6.5.3790.4523", dir:"\System32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Quartz.dll", version:"6.5.2600.3580", dir:"\System32") ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0",                   file:"Quartz.dll", version:"6.5.1.911", min_version:"6.5.0.0", dir:"\System32") ||
  hotfix_is_vulnerable(os:"5.0",                   file:"Quartz.dll", version:"6.3.1.893", min_version:"6.3.0.0", dir:"\System32") ||
  hotfix_is_vulnerable(os:"5.0",                   file:"Quartz.dll", version:"6.1.9.736",                        dir:"\System32")
)
{
  set_kb_item(name:"SMB/Missing/MS09-028", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end(); 
  exit(0);
}
else
{
  hotfix_check_fversion_end(); 
  exit(0, "The host is not affected.");
}
