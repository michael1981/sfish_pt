#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36149);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-0084");
  script_bugtraq_id(34460);
  script_xref(name:"OSVDB", value:"53632");

  script_name(english: "MS09-011: Vulnerability in Microsoft DirectShow Could Allow Remote Code Execution (961373)");
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
      "DirectX installed on the remote host is affected by a vulnerability\n",
      "that may allow execution of arbitrary code when decompressing a\n",
      "specially crafted MJPEG file."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for DirectX :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-011.mspx"
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


if (!get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/DirectX/Version")) exit(0);
if (hotfix_check_sp(win2k:6, xp:4, win2003:3) <= 0) exit(0);

if (is_accessible_share())
{
  if (
    # Windows 2003
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Quartz.dll", version:"6.5.3790.4431", min_version:"6.5.0.0", dir:"\System32") ||
    hotfix_is_vulnerable(os:"5.2", sp:1, file:"Quartz.dll", version:"6.5.3790.3266", min_version:"6.5.0.0", dir:"\System32") ||

    # Windows XP
    hotfix_is_vulnerable(os:"5.1", sp:3, file:"Quartz.dll", version:"6.5.2600.5731", min_version:"6.5.0.0", dir:"\System32") ||
    hotfix_is_vulnerable(os:"5.1", sp:2, file:"Quartz.dll", version:"6.5.2600.3497", min_version:"6.5.0.0", dir:"\System32") ||

    # Windows 2000
    hotfix_is_vulnerable(os:"5.0", file:"Quartz.dll", version:"6.5.1.910", min_version:"6.5.0.0", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.0", file:"Quartz.dll", version:"6.3.1.892", min_version:"6.3.0.0", dir:"\System32")
  ) {
 set_kb_item(name:"SMB/Missing/MS09-011", value:TRUE);
 hotfix_security_hole();
 }
 
  hotfix_check_fversion_end(); 
  exit(0);
}
