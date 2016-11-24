#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36150);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2008-1436", "CVE-2009-0078", "CVE-2009-0079", "CVE-2009-0080");
  script_bugtraq_id(28833, 34442, 34443, 34444);
  script_xref(name:"OSVDB", value:"44580");
  script_xref(name:"OSVDB", value:"53666");
  script_xref(name:"OSVDB", value:"53667");
  script_xref(name:"OSVDB", value:"53668");

  script_name(english: "MS09-012: Vulnerabilities in Windows Could Allow Elevation of Privilege (959454)");
  script_summary(english:"Checks version of Msdtcprx.dll / Ntoskrnl.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:"A local user can elevate his privileges on the remote host."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The version of Windows running on the remote host is affected by\n",
      "potentially four vulnerabilities involving its MSDTC transaction\n",
      "facility and/or Windows Service Isolation that may allow a local user\n",
      "to escalate his privileges and take complete control of the affected\n",
      "system."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Windows 2000, XP, 2003,\n",
      "Vista and 2008 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-012.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C"
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
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Ntoskrnl.exe", version:"6.0.6001.22389", min_version:"6.0.6000.20000", dir:"\System32") ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Msdtcprx.dll", version:"2001.12.6931.22197", min_version:"2001.12.6931.20000", dir:"\System32") ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Ntoskrnl.exe", version:"6.0.6001.18226", dir:"\System32") ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Msdtcprx.dll", version:"2001.12.6931.18085", dir:"\System32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Ntoskrnl.exe", version:"6.0.6000.21023", min_version:"6.0.6000.20000", dir:"\System32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Msdtcprx.dll", version:"2001.12.6930.20852", min_version:"2001.12.6930.20000", dir:"\System32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Ntoskrnl.exe", version:"6.0.6000.16830", dir:"\System32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Msdtcprx.dll", version:"2001.12.6930.16697", dir:"\System32") ||

    # Windows 2003
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Ntoskrnl.exe", version:"5.2.3790.4478", dir:"\System32") ||
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Msdtcprx.dll", version:"2001.12.4720.4340", dir:"\System32") ||
    hotfix_is_vulnerable(os:"5.2", sp:1, file:"Ntoskrnl.exe", version:"5.2.3790.3309", dir:"\System32") ||
    hotfix_is_vulnerable(os:"5.2", sp:1, file:"Msdtcprx.dll", version:"2001.12.4720.3180", dir:"\System32") ||

    # Windows XP
    hotfix_is_vulnerable(os:"5.1", sp:3, file:"Ntoskrnl.exe", version:"5.1.2600.5755", dir:"\System32") ||
    hotfix_is_vulnerable(os:"5.1", sp:3, file:"Msdtcprx.dll", version:"2001.12.4414.706", dir:"\System32") ||
    hotfix_is_vulnerable(os:"5.1", sp:2, file:"Ntoskrnl.exe", version:"5.1.2600.3520", dir:"\System32") ||
    hotfix_is_vulnerable(os:"5.1", sp:2, file:"Msdtcprx.dll", version:"2001.12.4414.320", dir:"\System32") ||

    # Windows 2000
    hotfix_is_vulnerable(os:"5.0", file:"Msdtcprx.dll", version:"2000.2.3549.0", dir:"\System32")
  ) {
 set_kb_item(name:"SMB/Missing/MS09-012", value:TRUE);
 hotfix_security_hole();
 }
 
  hotfix_check_fversion_end(); 
  exit(0);
}
