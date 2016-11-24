#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42107);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-0555", "CVE-2009-2525");
  script_bugtraq_id(36602, 36614);
  script_xref(name:"OSVDB", value:"58844");
  script_xref(name:"OSVDB", value:"58845");

  script_name(english:"MS09-051: Vulnerabilities in Windows Media Runtime Could Allow Remote Code Execution (975682)");
  script_summary(english:"Checks version of wmspdmod.dll and msaud32.acm");

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
      "Runtime that is affected by multiple vulnerabilities :\n",
      "\n",
      "  - The ASF parser incorrectly parses files which make use\n",
      "    of the Window Media Speech codec. A remote attacker can\n",
      "    exploit this by tricking a user into opening a specially\n",
      "    crafted ASF file, which can lead to arbitrary code\n",
      "    execution. (CVE-2009-0555)\n",
      "\n",
      "  - The Audio Compression Manager does not properly initialize\n",
      "    certain functions in compressed audio files. A remote\n",
      "    attacker can exploit this by tricking a user into opening\n",
      "    a specially crafted media file, which can lead to\n",
      "    arbitrary code execution. (CVE-2009-2525)"
    )
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Microsoft has released a set of patches for Windows 2000, XP, 2003,\n",
      "Vista and 2008 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/bulletin/MS09-051.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
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
if ( hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:3) <= 0 )
  exit(0, "The host is not affected based on its version / service pack.");
if ( !is_accessible_share() )
  exit(1, "is_accessible_share() failed.");

if (
  # Vista / Windows 2008
  # WMFR 11 x86 and x64
  hotfix_is_vulnerable(os:"6.0", sp:0,  file:"wmspdmod.dll", version:"11.0.6000.6350",  dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:0,  file:"wmspdmod.dll", version:"11.0.6000.6509",  min_version:"11.0.6000.6500", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,  file:"wmspdmod.dll", version:"11.0.6001.7005",  dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,  file:"wmspdmod.dll", version:"11.0.6001.7111",  min_version:"11.0.6001.7100", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:2,  file:"wmspdmod.dll", version:"11.0.6002.18034", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:2,  file:"wmspdmod.dll", version:"11.0.6002.22131", min_version:"11.0.6002.22000", dir:"\system32") ||

  # Windows 2003 x64
  hotfix_is_vulnerable(os:"5.2", arch:"x64", file:"wmavds32.ax",  version:"9.0.0.3360",     min_version:"9.0.0.0", dir:"\SysWOW64") ||
  hotfix_is_vulnerable(os:"5.2", arch:"x64", file:"msaud32.acm",  version:"8.0.0.4502",     min_version:"8.0.0.0", dir:"\SysWOW64") ||
  hotfix_is_vulnerable(os:"5.2", arch:"x64", file:"wmspdmod.dll", version:"10.0.0.3712",    min_version:"10.0.0.3000", dir:"\SysWOW64") ||
  hotfix_is_vulnerable(os:"5.2", arch:"x64", file:"wmspdmod.dll", version:"10.0.0.4004",    min_version:"10.0.0.3900", dir:"\SysWOW64") ||
  hotfix_is_vulnerable(os:"5.2", arch:"x64", file:"wmspdmod.dll", version:"11.0.5721.5263", min_version:"11.0.0.0", dir:"\SysWOW64") ||

   # Windows 2003 x86
  hotfix_is_vulnerable(os:"5.2", arch:"x86", file:"wmavds32.ax",  version:"9.0.0.3360",     min_version:"9.0.0.0", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.2", arch:"x86", file:"msaud32.acm",  version:"8.0.0.4502",     min_version:"8.0.0.0", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.2", arch:"x86", file:"wmspdmod.dll", version:"10.0.0.3712",    min_version:"10.0.0.3000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.2", arch:"x86", file:"wmspdmod.dll", version:"10.0.0.4004",    min_version:"10.0.0.3900", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.2", arch:"x86", file:"wmspdmod.dll", version:"11.0.5721.5263", min_version:"11.0.0.0", dir:"\system32") ||

  # Windows XP x64
  hotfix_is_vulnerable(os:"5.1", arch:"x64", file:"wmavds32.ax",  version:"9.0.0.3360",     min_version:"9.0.0.0", dir:"\SysWOW64") ||
  hotfix_is_vulnerable(os:"5.1", arch:"x64", file:"msaud32.acm",  version:"8.0.0.4502",     min_version:"8.0.0.0", dir:"\SysWOW64") ||
  hotfix_is_vulnerable(os:"5.1", arch:"x64", file:"wmspdmod.dll", version:"10.0.0.3819",    min_version:"10.0.0.3000", dir:"\SysWOW64") ||
  hotfix_is_vulnerable(os:"5.1", arch:"x64", file:"wmspdmod.dll", version:"11.0.5721.5263", min_version:"11.0.0.0", dir:"\SysWOW64") ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", arch:"x86", file:"wmavds32.ax",   version:"9.0.0.3360",    min_version:"9.0.0.0", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", arch:"x86", file:"msaud32.acm",   version:"8.0.0.4502",    min_version:"8.0.0.0", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"wmspdmod.dll", version:"9.0.0.3269", min_version:"9.0.0.0", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"wmspdmod.dll", version:"9.0.0.4505", min_version:"9.0.0.4000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", arch:"x86", file:"wmspdmod.dll",   version:"10.0.0.3704",    min_version:"10.0.0.3000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", arch:"x86", file:"wmspdmod.dll",   version:"10.0.0.4070",    min_version:"10.0.0.3800", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", arch:"x86", file:"wmspdmod.dll",   version:"10.0.0.4365",    min_version:"10.0.0.4300", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", arch:"x86", file:"wmspdmod.dll",   version:"11.0.5721.5263", min_version:"11.0.0.0", dir:"\system32") ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0", file:"wmspdmod.dll",   version:"9.0.0.3269",   min_version:"9.0.0.0", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.0", file:"wmspdmod.dll",   version:"10.0.0.4070",  min_version:"10.0.0.0", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.0", file:"wmavds32.ax",   version:"9.0.0.3360",    min_version:"9.0.0.0", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.0", file:"msaud32.acm",   version:"8.0.0.4502",    min_version:"8.0.0.0", dir:"\system32")

)
{
  set_kb_item(name:"SMB/Missing/MS09-051", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected.");
}
