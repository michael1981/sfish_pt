#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39344);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-0228", "CVE-2009-0229", "CVE-2009-0230");
  script_bugtraq_id(35206, 35208, 35209);
  script_xref(name:"OSVDB", value:"54932");
  script_xref(name:"OSVDB", value:"54933");
  script_xref(name:"OSVDB", value:"54934");

  script_name(english:"MS09-022: Vulnerabilities in Windows Print Spooler Could Allow Remote Code Execution (961501)");
  script_summary(english:"Checks version of Localspl.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "Arbitrary code can be executed on the remote host due to a flaw in the\n",
      "Spooler service."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The version of the Print Spooler service on the remote Windows host is\n",
      "affected by one or more of the following vulnerabilities :\n",
      "\n",
      "  - A buffer overflow vulnerability could allow an \n",
      "    unauthenticated remote attacker to execute arbitrary\n",
      "    code with SYSTEM privileges. (CVE-2009-0228)\n",
      "\n",
      "  - Using a specially crafted separator page, a local user\n",
      "    can read or print any file on the affected system.\n",
      "    (CVE-2009-0229)\n",
      "\n",
      "  - Using a specially crafted RPC message, a user who has\n",
      "    the 'Manage Printer' privilege can have the spooler\n",
      "    load an arbitrary DLL and thereby execute arbitrary\n",
      "    code with elevated privileges. (CVE-2009-0230)"
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Windows 2000, XP, 2003,\n",
      "Vista and 2008 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-022.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
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
    # Vista / Windows 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Localspl.dll", version:"6.0.6002.22120", min_version:"6.0.6002.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Localspl.dll", version:"6.0.6002.18024",                               dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Localspl.dll", version:"6.0.6001.22417", min_version:"6.0.6001.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Localspl.dll", version:"6.0.6001.18247",                               dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Localspl.dll", version:"6.0.6000.21045", min_version:"6.0.6000.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Localspl.dll", version:"6.0.6000.16850",                               dir:"\system32") ||

    # Windows 2003
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Localspl.dll", version:"5.2.3790.4509", dir:"\system32") ||

    # Windows XP
    hotfix_is_vulnerable(os:"5.1", sp:3,             file:"Localspl.dll", version:"5.1.2600.5809", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Localspl.dll", version:"5.2.3790.4509", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Localspl.dll", version:"5.1.2600.3569", dir:"\system32") ||

    # Windows 2000
    hotfix_is_vulnerable(os:"5.0", file:"Localspl.dll", version:"5.0.2195.7296", dir:"\system32")
  )
  {
    set_kb_item(name:"SMB/Missing/MS09-022", value:TRUE);
    hotfix_security_hole();
  }

  hotfix_check_fversion_end(); 
  exit(0);
}
