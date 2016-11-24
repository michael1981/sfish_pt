#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39792);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-0231", "CVE-2009-0232");
  script_bugtraq_id(35186, 35187);
  script_xref(name:"OSVDB", value:"55842");
  script_xref(name:"OSVDB", value:"55843");

  script_name(english:"MS09-029: Vulnerabilities in the Embedded OpenType Font Engine Could Allow Remote Code Execution (961371)");
  script_summary(english:"Checks version of T2embed.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "It is possible to execute arbitrary code on the remote Windows host\n",
      "using the Embedded OpenType Font Engine."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote Windows host contains a version of the Embedded OpenType\n",
      "(EOT) Font Engine that is affected by multiple buffer overflow\n",
      "vulnerabilities due to the way the EOT font technology parses name\n",
      "tables in specially crafted embedded fonts.\n",
      "\n",
      "If an attacker can trick a user on the affected system into viewing\n",
      "content rendered in a specially crafted EOT font, he may be able to\n",
      "leverage these issues to execute arbitrary code subject to the user's\n",
      "privileges."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Windows 2000, XP, 2003,\n",
      "Vista and 2008 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-029.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/07/14"
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


if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:3) <= 0) exit(0, "Host is not affected based on its version / service pack.");

if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");


if (
  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"T2embed.dll", version:"6.0.6002.22152", min_version:"6.0.6002.20000", dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"T2embed.dll", version:"6.0.6002.18051",                               dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"T2embed.dll", version:"6.0.6001.22450", min_version:"6.0.6001.20000", dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"T2embed.dll", version:"6.0.6001.18272",                               dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"T2embed.dll", version:"6.0.6000.21067", min_version:"6.0.6000.20000", dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"T2embed.dll", version:"6.0.6000.16870",                               dir:"\System32") ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"T2embed.dll", version:"5.2.3790.4530", dir:"\System32") ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"T2embed.dll", version:"5.1.2600.5830", dir:"\System32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"T2embed.dll", version:"5.2.3790.4530", dir:"\System32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"T2embed.dll", version:"5.1.2600.3589", dir:"\System32") ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0",                   file:"T2embed.dll", version:"5.0.2195.7263", dir:"\System32")
)
{
  set_kb_item(name:"SMB/Missing/MS09-029", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end(); 
  exit(0);
}
else
{
  hotfix_check_fversion_end(); 
  exit(0, "The host is not affected.");
}
