#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36152);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-2540", "CVE-2009-0550", "CVE-2009-0551", "CVE-2009-0552", "CVE-2009-0553", "CVE-2009-0554");
  script_bugtraq_id(29445, 34423, 34424, 34426, 34438);
  script_xref(name:"OSVDB", value:"53619");
  script_xref(name:"OSVDB", value:"53623");
  script_xref(name:"OSVDB", value:"53624");
  script_xref(name:"OSVDB", value:"53625");
  script_xref(name:"OSVDB", value:"53626");
  script_xref(name:"OSVDB", value:"53627");

  script_name(english: "MS09-014: Cumulative Security Update for Internet Explorer (963027)");
  script_summary(english:"Checks version of Mshtml.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "Arbitrary code can be executed on the remote host through a web\n",
      "browser."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is missing IE Security Update 963027.\n",
      "\n",
      "The remote version of IE is affected by several vulnerabilities that\n",
      "may allow an attacker to execute arbitrary code on the remote host."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Windows 2000, XP, 2003,\n",
      "Vista and 2008 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-014.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
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


if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:2) <= 0) exit(0);

if (is_accessible_share())
{
  if (
    # Vista / Windows 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.20613", min_version:"7.0.6002.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Mshtml.dll", version:"7.0.6001.22389", min_version:"7.0.6001.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Mshtml.dll", version:"7.0.6001.18226", min_version:"7.0.0.0", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.21023", min_version:"7.0.6000.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.16830", min_version:"7.0.0.0", dir:"\system32") ||

    # Windows 2003
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"7.0.6000.21015", min_version:"7.0.6000.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"7.0.6000.16825", min_version:"7.0.0.0", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"6.0.3790.4470", min_version:"6.0.0.0", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.2", sp:1, file:"Mshtml.dll", version:"6.0.3790.3304", min_version:"6.0.0.0", dir:"\system32") ||

    # Windows XP
    hotfix_is_vulnerable(os:"5.1", sp:3,             file:"Mshtml.dll", version:"7.0.6000.21015", min_version:"7.0.6000.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.1", sp:3,             file:"Mshtml.dll", version:"7.0.6000.16825", min_version:"7.0.0.0", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.1",       arch:"x64", file:"Mshtml.dll", version:"6.0.3790.4470", min_version:"6.0.3790.0", dir:"\System32") ||
    hotfix_is_vulnerable(os:"5.1",       arch:"x64", file:"Mshtml.dll", version:"6.0.3790.3304", min_version:"6.0.0.0", dir:"\System32") ||
    hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Mshtml.dll", version:"6.0.2900.5764", min_version:"6.0.0.0", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.1", sp:2,             file:"Mshtml.dll", version:"7.0.6000.16825", min_version:"7.0.0.0", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Mshtml.dll", version:"6.0.2900.3527", min_version:"6.0.0.0", dir:"\system32") ||

    # Windows 2000
    hotfix_is_vulnerable(os:"5.0", file:"Msrating.dll", version:"6.0.2800.1958", min_version:"6.0.0.0", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.0", file:"Mshtml.dll", version:"5.0.3874.1900", min_version:"5.0.0.0", dir:"\system32")
  ) {
 set_kb_item(name:"SMB/Missing/MS09-014", value:TRUE);
 hotfix_security_hole();
 }
 
  hotfix_check_fversion_end(); 
  exit(0);
}
