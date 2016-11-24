#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42115);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-2524");
  script_bugtraq_id(36593);
  script_xref(name:"OSVDB", value:"58862");

  script_name(english:"MS09-059: Vulnerability in Local Security Authority Subsystem Service Could Allow Denial of Service (975467)");
  script_summary(english:"Checks version of msv1_0.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Windows host is prone to a denial of service attack."
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of LSASS running on the remote host has an integer overflow\n",
      "vulnerability.  A remote attacker could exploit this to cause a denial of\n",
      "service."
    )
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Microsoft has released a set of patches for Windows 2000, XP, 2003,\n",
      "Vista and 2008 and 7 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-059.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C"
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
if (hotfix_check_sp(xp:4, win2003:3, vista:3, win7:1) <= 0) exit(0, "The host is not affected based on its version / service pack.");

if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

if (
  # Windows 7
  hotfix_is_vulnerable(os:"6.1",       file:"Msv1_0.dll", version:"6.1.7600.20524", min_version:"6.1.7600.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.1",       file:"Msv1_0.dll", version:"6.1.7600.16420", min_version:"6.1.7600.16000", dir:"\system32") ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Msv1_0.dll", version:"6.0.6002.22223", min_version:"6.0.6002.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Msv1_0.dll", version:"6.0.6002.18111", min_version:"6.0.6002.18000",        dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Msv1_0.dll", version:"6.0.6001.22518", min_version:"6.0.6001.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Msv1_0.dll", version:"6.0.6001.18330", min_version:"6.0.6001.18000",        dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Msv1_0.dll", version:"6.0.6000.21125", min_version:"6.0.6000.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Msv1_0.dll", version:"6.0.6000.16926", min_version:"6.0.6000.16000",        dir:"\system32") ||

  # Windows 2003 & XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Msv1_0.dll", version:"5.2.3790.4587", min_version:"5.2.3790.4530", dir:"\system32") ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Msv1_0.dll",       version:"5.1.2600.5876",  min_version:"5.1.2600.5834",        dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Msv1_0.dll",       version:"5.1.2600.3625",  min_version:"5.1.2600.3592", dir:"\system32")
)
{
  set_kb_item(name:"SMB/Missing/MS09-059", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected");
}

