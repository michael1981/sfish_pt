#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40888);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-1920");
  script_bugtraq_id(36224);
  script_xref(name:"OSVDB", value:"57804");

  script_name(english:"MS09-045: Vulnerability in JScript Scripting Engine Could Allow Remote Code Execution (971961)");
  script_summary(english:"Checks version of Jscript.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "Arbitrary code can be executed on the remote host through the web or\n",
      "email client."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running a version of Windows that contains a flaw\n",
      "in its JScript scripting engine.\n",
      "\n",
      "An attacker may be able to execute arbitrary code on the remote host\n",
      "by constructing a malicious JScript and enticing a victim to visit a\n",
      "web site or view a specially crafted email message."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Windows 2000, XP, 2003,\n",
      "Vista and 2008 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-045.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
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
if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");

if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:3) <= 0) exit(0, "The host is not affected based on its version / service pack.");
if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");


if (
  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0",                   file:"Jscript.dll", version:"5.8.6001.22886", min_version:"5.8.6001.22000", dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Jscript.dll", version:"5.8.6001.18795", min_version:"5.8.0.0",        dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Jscript.dll", version:"5.7.6002.22146", min_version:"5.7.6002.20000", dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Jscript.dll", version:"5.7.6002.18045", min_version:"5.7.6002.0",     dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Jscript.dll", version:"5.7.0.22443",    min_version:"5.7.0.22000",    dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Jscript.dll", version:"5.7.0.21061",    min_version:"5.7.0.20000",    dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Jscript.dll", version:"5.7.0.18266",    min_version:"5.7.0.18000",    dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Jscript.dll", version:"5.7.0.16865",    min_version:"5.7.0.0",        dir:"\System32") ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Jscript.dll", version:"5.8.6001.22886", min_version:"5.8.0.0",        dir:"\System32") ||
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Jscript.dll", version:"5.7.6002.22145", min_version:"5.7.0.0",        dir:"\System32") ||
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Jscript.dll", version:"5.6.0.8837",                                   dir:"\System32") ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Jscript.dll", version:"5.8.6001.22886", min_version:"5.8.0.0",        dir:"\System32") ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Jscript.dll", version:"5.7.6002.22145", min_version:"5.7.0.0",        dir:"\System32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2,             file:"Jscript.dll", version:"5.8.6001.22886", min_version:"5.8.0.0",        dir:"\System32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2,             file:"Jscript.dll", version:"5.7.6002.22145", min_version:"5.7.0.0",        dir:"\System32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2,             file:"Jscript.dll", version:"5.6.0.8837",                                   dir:"\System32") ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0",                   file:"Jscript.dll", version:"5.6.0.8837",                                   dir:"\System32")
)
{
  set_kb_item(name:"SMB/Missing/MS09-045", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end(); 
  exit(0);
}
hotfix_check_fversion_end(); 
exit(0, "The host is not affected.");
