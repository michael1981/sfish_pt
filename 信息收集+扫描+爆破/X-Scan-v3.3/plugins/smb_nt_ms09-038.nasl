#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40557);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-1545", "CVE-2009-1546");
  script_bugtraq_id(35967, 35970);
  script_xref(name:"OSVDB", value:"56908");
  script_xref(name:"OSVDB", value:"56909");

  script_name(english:"MS09-038: Vulnerabilities in Windows Media File Processing Could Allow Remote Code Execution (971557)");
  script_summary(english:"Checks version of Avifil32.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "Arbitrary code can be executed on the remote host through Windows\n",
      "Media file processing."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote Windows host is affected by two vulnerabilities involving\n",
      "the way in which AVI headers are processed and AVI data is validated\n",
      "that could be abused to execute arbitrary code remotely.\n",
      "\n",
      "If an attacker can trick a user on the affected system into opening\n",
      "a specially crafted AVI file, he may be able to leverage these issues\n",
      "to execute arbitrary code subject to the user's privileges.\n"
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Windows 2000, XP, 2003,\n",
      "Vista and 2008 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-038.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/08/11"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/08/11"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/11"
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


if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:3) <= 0) exit(0, "Host is not affected based on its version / service pack.");
if (hotfix_check_server_core() == 1) exit(0, "Windows Server Core installs are not affected.");

if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");


if (
  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Avifil32.dll", version:"6.0.6002.22150", min_version:"6.0.6002.20000", dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Avifil32.dll", version:"6.0.6002.18049",                               dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Avifil32.dll", version:"6.0.6001.22447", min_version:"6.0.6001.20000", dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Avifil32.dll", version:"6.0.6001.18270",                               dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Avifil32.dll", version:"6.0.6000.21065", min_version:"6.0.6000.20000", dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Avifil32.dll", version:"6.0.6000.16868",                               dir:"\System32") ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Avifil32.dll", version:"5.2.3790.4527", dir:"\System32") ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Avifil32.dll", version:"5.1.2600.5827", dir:"\System32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Avifil32.dll", version:"5.2.3790.4527", dir:"\System32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Avifil32.dll", version:"5.1.2600.3585", dir:"\System32") ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0",                   file:"Avifil32.dll", version:"5.0.2195.7316", dir:"\System32")
)
{
  set_kb_item(name:"SMB/Missing/MS09-038", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end(); 
  exit(0);
}
else
{
  hotfix_check_fversion_end(); 
  exit(0, "The host is not affected.");
}
