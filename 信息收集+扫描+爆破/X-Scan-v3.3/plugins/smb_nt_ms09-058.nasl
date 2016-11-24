#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42114);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-2515", "CVE-2009-2516", "CVE-2009-2517");
  script_bugtraq_id(36623, 36624, 36625);
  script_xref(name:"OSVDB", value:"58859");
  script_xref(name:"OSVDB", value:"58860");
  script_xref(name:"OSVDB", value:"58861");

  script_name(english:"MS09-058: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (971486)");
  script_summary(english:"Checks version of ntoskrnl.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The Windows kernel is vulnerable to multiple buffer overlfow attacks."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote Windows host is running a version of the Windows kernel\n",
      "that is affected by multiple vulnerabilities :\n",
      "\n",
      "  - An elevation of privilege vulnerability exists in the\n",
      "    Windows kernel due to the incorrect truncation of a 64-\n",
      "    bit value to a 32-bit value.  An attacker who\n",
      "    successfully exploited this vulnerability could run\n",
      "    arbitrary code in kernel mode. An attacker could then\n",
      "    install programs, view / change / delete data, or\n",
      "    create new accounts with full user rights.\n",
      "    (CVE-2009-2515)\n",
      "\n",
      "  - An elevation of privilege vulnerability exists in the \n",
      "    Windows kernel due to the incorrect truncation of a 64-\n",
      "    bit value to a 32-bit value.  An attacker who\n",
      "    successfully exploited this vulnerability could run\n",
      "    arbitrary code in kernel mode. An attacker could then\n",
      "    install programs, view / change / delete data, or\n",
      "    create new accounts with full user rights.\n",
      "    (CVE-2009-2516)\n",
      "\n",
      "  - A denial of service vulnerability exists in the Windows\n",
      "    kernel because of the way the kernel handles certain\n",
      "    exceptions.  An attacker could exploit the\n",
      "    vulnerability by running a specially crafted\n",
      "    application causing the system to restart.\n",
      "    (CVE-2009-2517)"
    )
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Microsoft has released a set of patches for Windows 2000, XP, 2003,\n",
      "Vista and 2008 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/bulletin/MS09-058.mspx"
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

if ( !get_kb_item("SMB/WindowsVersion") )
  exit(1, "The 'SMB/WindowsVersion' KB item is missing.");
if ( hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:3 ) <= 0 )
  exit(0, "The host is not affected based on its version / service pack.");
if ( !is_accessible_share() )
  exit(1, "is_accessible_share() failed.");

if (
  # Vista / 2k8
  hotfix_is_vulnerable(os:"6.0", sp:0,  file:"ntoskrnl.exe", version:"6.0.6000.16901", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:0,  file:"ntoskrnl.exe", version:"6.0.6000.21101", min_version:"6.0.6000.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,  file:"ntoskrnl.exe", version:"6.0.6001.18304", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,  file:"ntoskrnl.exe", version:"6.0.6001.22489", min_version:"6.0.6001.22000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:2,  file:"ntoskrnl.exe", version:"6.0.6002.18082", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:2,  file:"ntoskrnl.exe", version:"6.0.6002.22191", min_version:"6.0.6002.22000", dir:"\system32") ||

  # Windows 2003 x86 and x64
  hotfix_is_vulnerable(os:"5.2", file:"ntoskrnl.exe", version:"5.2.3790.4566", min_version:"5.2.0.0", dir:"\system32") ||

  # Windows XP x64
  hotfix_is_vulnerable(os:"5.1", arch:"x64", file:"ntoskrnl.exe", version:"5.2.3790.4566", min_version:"5.2.0.0", dir:"\system32") ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"ntoskrnl.exe", version:"5.1.2600.3610", min_version:"5.1.0.0", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"ntoskrnl.exe", version:"5.1.2600.5857", min_version:"5.1.0.0", dir:"\system32") ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0", file:"ntoskrnl.exe", version:"5.0.2195.7319", min_version:"5.0.0.0", dir:"\system32")

)
{
  set_kb_item(name:"SMB/Missing/MS09-058", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected.");
}
