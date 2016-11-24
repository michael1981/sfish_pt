#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42113);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-2507");
  script_bugtraq_id(36629);
  script_xref(name:"OSVDB", value:"58854");

  script_name(english:"MS09-057: Vulnerability in Indexing Service Could Allow Remote Code Execution (969059)");
  script_summary(english:"Checks the version of query.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Windows host has an ActiveX control that is affected by\n",
      "a code execution vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote host contains the ixsso.dll ActiveX control.\n\n",
      "This control is included with the Indexing Service.  The version of this\n",
      "control installed on the remote host reportedly has an arbitrary code\n",
      "execution vulnerability.  A remote attacker could exploit this by tricking\n",
      "a user into requesting a maliciously crafted web page.\n\n",
      "This vulnerability only affects systems that have the Indexing Service\n",
      "enabled.  It is disabled by default."
    )
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Microsoft has released a set of patches for Windows 2000, XP, and 2003 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-057.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C"
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
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if (!get_kb_item("SMB/WindowsVersion")) exit(1, "The 'SMB/WindowsVersion' KB item is missing.");
if (hotfix_check_sp(win2k:6, xp:3, win2003:3) <= 0) exit(0, "The host is not affected based on its version / service pack.");
if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

if (
  # 2k3
  hotfix_is_vulnerable(os:"5.2", file:"query.dll", version:"5.2.3790.4554", dir:"\system32") ||

  # XP
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"query.dll",                 version:"5.1.2600.5847",   min_version:"5.1.2600.5000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"query.dll",                 version:"5.2.3790.4554", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"query.dll",                 version:"5.1.2600.3602",   dir:"\system32") ||

  # 2000
  hotfix_is_vulnerable(os:"5.0", sp:4,  file:"query.dll", version:"5.0.2195.7320",   dir:"\system32")
)
{
  set_kb_item(name:"SMB/Missing/MS09-057", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected");
}


