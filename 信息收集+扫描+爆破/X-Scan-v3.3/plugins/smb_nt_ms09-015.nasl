#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36153);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2008-2540");
  script_bugtraq_id(29445);
  script_xref(name:"OSVDB", value:"53623");

  script_name(english: "MS09-015: Blended Threat Vulnerability in SearchPath Could Allow Elevation of Privilege (959426)");
  script_summary(english:"Checks version of Secur32.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host may allow remote code execution."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "A vulnerability in the way the Windows SearchPath function locates and\n",
      "opens files on the remote host could allow an attacker to execute\n",
      "arbitrary remote code if he can trick a user into downloading a\n",
      "specially crafted file into a specific location, such as the Windows\n",
      "Desktop."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Windows 2000, XP, 2003,\n",
      "Vista and 2008 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-015.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N"
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
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Secur32.dll", version:"6.0.6001.22376", min_version:"6.0.6001.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Secur32.dll", version:"6.0.6001.18215", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Secur32.dll", version:"6.0.6000.21010", min_version:"6.0.6000.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Secur32.dll", version:"6.0.6000.16820", dir:"\system32") ||

    # Windows 2003
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Secur32.dll", version:"5.2.3790.4455", dir:"\System32") ||
    hotfix_is_vulnerable(os:"5.2", sp:1, file:"Secur32.dll", version:"5.2.3790.3290", dir:"\System32") ||

    # Windows XP
    hotfix_is_vulnerable(os:"5.1",       arch:"x64", file:"Secur32.dll", version:"5.2.3790.4455", min_version:"5.2.3790.4000", dir:"\System32") ||
    hotfix_is_vulnerable(os:"5.1",       arch:"x64", file:"Secur32.dll", version:"5.2.3790.3290", min_version:"5.2.0.0", dir:"\System32") ||
    hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Secur32.dll", version:"5.1.2600.5753", dir:"\System32") ||
    hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Secur32.dll", version:"5.1.2600.3518", dir:"\System32") ||

    # Windows 2000
    hotfix_is_vulnerable(os:"5.0", file:"Secur32.dll", version:"5.0.2195.7244", dir:"\System32")
  ) {
    set_kb_item(name:"SMB/Missing/MS09-015", value:TRUE);
    hotfix_security_warning();
 }
 
  hotfix_check_fversion_end(); 
  exit(0);
}
