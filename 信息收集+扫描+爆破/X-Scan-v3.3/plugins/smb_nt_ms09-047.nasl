#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40890);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-2498", "CVE-2009-2499");
  script_bugtraq_id(36225, 36228);
  script_xref(name:"OSVDB", value:"57802");
  script_xref(name:"OSVDB", value:"57803");

  script_name(english:"MS09-047: Vulnerabilities in Windows Media Format Could Allow Remote Code Execution (973812)");
  script_summary(english:"Checks version of wmvcore.dll / wmsserver.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "Arbitrary code can be executed on the remote host through opening a\n",
      "Windows Media Format file."
    ) 
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote Windows host contains a version of the Windows Media\n",
      "Format Runtime or Windows Media Services that is affected by multiple\n",
      "vulnerabilities :\n",
      "\n",
      "  - The ASF parser has an invalid free vulnerability.\n",
      "    A remote attacker could exploit this by tricking a\n",
      "    user into opening a specially crafted ASF file, which\n",
      "    could lead to arbitrary code execution. (CVE-2009-2498)\n",
      "\n",
      "  - The MP3 parser has a memory corruption vulnerability.\n",
      "    A remote attacker could exploit this by tricking a\n",
      "    user into opening a specially crafted MP3 file, which\n",
      "    could lead to arbitrary code execution. (CVE-2009-2499)"
    )
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Microsoft has released a set of patches for Windows 2000, XP, 2003,\n",
      "Vista and 2008 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/bulletin/MS09-047.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/09/08"
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
if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:3) <= 0) exit(0, "The host is not affected based on its version / service pack.");

if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

if (
  # Vista / Windows 2008
  # WMFR 11
  hotfix_is_vulnerable(os:"6.0",   file:"wmvcore.dll", version:"11.0.6000.6351", min_version:"10.0.6000.6300", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0",   file:"wmvcore.dll", version:"11.0.6000.6510", min_version:"10.0.6000.6500", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0",   file:"wmvcore.dll", version:"11.0.6001.7006", min_version:"10.0.6001.7000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0",   file:"wmvcore.dll", version:"11.0.6001.7113", min_version:"10.0.6002.7100", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0",   file:"wmvcore.dll", version:"11.0.6002.18049", min_version:"10.0.6002.18000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0",   file:"wmvcore.dll", version:"11.0.6002.22150", min_version:"10.0.6002.22000", dir:"\system32") ||
  # WMS
  hotfix_is_vulnerable(os:"6.0", file:"Wmsserver.dll", version:"9.5.6001.18281", dir:"\system32\windows media\server") ||

  # Windows 2003
  # WMFR 9.5
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"Wmvcore.dll", version:"10.0.0.4005", min_version:"10.0.0.0", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Wmvcore.dll", version:"10.0.0.4005", min_version:"10.0.0.0", dir:"\SysWOW64") ||
  # Windows Media Services
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"Wmsserver.dll", version:"9.1.1.5001", dir:"\system32\windows media\server") ||
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Wmsserver.dll", version:"9.1.1.5001", dir:"\system32\windows media\server") ||
  

  # Windows XP
  # WMFR 9.5, and 11 for XP x86 SP2 and SP3
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Wmvcore.dll",  version:"10.0.0.4372", min_version:"10.0.0.4300", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmvcore.dll",  version:"10.0.0.4372", min_version:"10.0.0.4300", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Wmvcore.dll",  version:"10.0.0.3705", min_version:"10.0.0.3700", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmvcore.dll",  version:"10.0.0.3705", min_version:"10.0.0.3700", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Wmvcore.dll",  version:"10.0.0.4072", min_version:"10.0.0.4000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmvcore.dll",  version:"10.0.0.4072", min_version:"10.0.0.4000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Wmvcore.dll",  version:"11.0.5721.5265", min_version:"11.0.0.0", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmvcore.dll",  version:"11.0.5721.5265", min_version:"11.0.0.0", dir:"\system32") ||

  # WMFR 9.0 for XP x86 SP2
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Wmvcore.dll",  version:"9.0.0.3270", min_version:"9.0.0.0", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Wmvcore.dll",  version:"9.0.0.3362", min_version:"9.0.0.3300", dir:"\system32") ||

  # WMFR 9.0 for XP x86 SP3
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmvcore.dll",  version:"9.0.0.4506", min_version:"9.0.0.0", dir:"\system32") ||

  # WMFR 9.5 and 11 for XP x64 SP2
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Wwmvcore.dll", version:"10.0.0.4005", min_version:"10.0.0.0", dir:"\SysWOW64") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Wmvcore.dll",  version:"11.0.5721.5265", min_version:"11.0.0.0", dir:"\SysWOW64") ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0", file:"Wmvcore.dll",   version:"9.0.0.3270",    min_version:"9.0.0.0", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.0", file:"Wmvcore.dll",   version:"9.0.0.3362",    min_version:"9.0.0.3300", dir:"\system32")
)
{
  set_kb_item(name:"SMB/Missing/MS09-047", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected.");
}
