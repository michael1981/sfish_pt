#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39341);
  script_version("$Revision: 1.3 $");

  script_cve_id(
    "CVE-2007-3091", 
    "CVE-2009-1140", 
    "CVE-2009-1141", 
    "CVE-2009-1528",
    "CVE-2009-1529", 
    "CVE-2009-1530", 
    "CVE-2009-1531", 
    "CVE-2009-1532"
  );
  script_bugtraq_id(24283, 35198, 35200, 35222, 35223, 35224, 35234, 35235);
  script_xref(name:"OSVDB", value:"38497");
  script_xref(name:"OSVDB", value:"54944");
  script_xref(name:"OSVDB", value:"54945");
  script_xref(name:"OSVDB", value:"54946");
  script_xref(name:"OSVDB", value:"54947");
  script_xref(name:"OSVDB", value:"54948");
  script_xref(name:"OSVDB", value:"54949");
  script_xref(name:"OSVDB", value:"54950");
  script_xref(name:"OSVDB", value:"54951");

  script_name(english:"MS09-019: Cumulative Security Update for Internet Explorer (969897)");
  script_summary(english:"Checks version of Mshtml.dll / MSrating.dll");

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
     "The remote host is missing IE Security Update 969897.\n",
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
      "http://www.microsoft.com/technet/security/Bulletin/MS09-019.mspx"
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


if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:3) <= 0) exit(0);

if (is_accessible_share())
{
  if (
    # Vista / Windows 2008
    hotfix_is_vulnerable(os:"6.0",       file:"Mshtml.dll", version:"8.0.6001.22874", min_version:"8.0.6001.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0",       file:"Mshtml.dll", version:"8.0.6001.18783", min_version:"8.0.0.0", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.22121", min_version:"7.0.6002.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.18024", min_version:"7.0.0.0", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Mshtml.dll", version:"7.0.6001.22418", min_version:"7.0.6001.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Mshtml.dll", version:"7.0.6001.18248", min_version:"7.0.0.0", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.21046", min_version:"7.0.6000.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.16851", min_version:"7.0.0.0", dir:"\system32") ||

    # Windows 2003
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"8.0.6001.22873", min_version:"8.0.6001.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"8.0.6001.18783", min_version:"8.0.0.0", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"7.0.6000.21045", min_version:"7.0.6000.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"7.0.6000.16850", min_version:"7.0.0.0", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"6.0.3790.4504", min_version:"6.0.0.0", dir:"\system32") ||

    # Windows XP
    hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Mshtml.dll", version:"8.0.6001.22873", min_version:"8.0.6001.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Mshtml.dll", version:"8.0.6001.18783", min_version:"8.0.0.0", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Mshtml.dll", version:"8.0.6001.22873", min_version:"8.0.6001.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Mshtml.dll", version:"8.0.6001.18783", min_version:"8.0.0.0", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mshtml.dll", version:"7.0.6000.21045", min_version:"7.0.6000.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mshtml.dll", version:"7.0.6000.16850", min_version:"7.0.0.0", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mshtml.dll", version:"6.0.2900.5803", min_version:"6.0.0.0", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.1", sp:2, file:"Mshtml.dll", version:"7.0.6000.16850", min_version:"7.0.0.0", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2900.3562", min_version:"6.0.0.0", dir:"\system32") ||

    # Windows 2000
    hotfix_is_vulnerable(os:"5.0", file:"Msrating.dll", version:"6.0.2800.1972", min_version:"6.0.0.0", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.0", file:"Mshtml.dll", version:"5.0.3877.2200", min_version:"5.0.0.0", dir:"\system32")
  )
  {
    set_kb_item(name:"SMB/Missing/MS09-019", value:TRUE);
    hotfix_security_hole();
  }

  hotfix_check_fversion_end(); 
  exit(0);
}
