#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40407);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-1917", "CVE-2009-1918", "CVE-2009-1919");
  script_bugtraq_id(35826, 35827, 35831);
  script_xref(name:"OSVDB", value:"56693");
  script_xref(name:"OSVDB", value:"56694");
  script_xref(name:"OSVDB", value:"56695");

  script_name(english:"MS09-034: Cumulative Security Update for Internet Explorer (972260)");
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
     "The remote host is missing IE Security Update 972260.\n",
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
      "http://www.microsoft.com/technet/security/Bulletin/MS09-034.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/07/28"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/07/28"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/07/28"
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


if (!get_kb_item("SMB/WindowsVersion")) exit(1, "SMB/WindowsVersion KB item is missing.");
if (hotfix_check_server_core() == 1) exit(0, "Windows Server Core installs are not affected.");
if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:3) <= 0) exit(0, "Host is not affected based on its version / service pack.");

if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

if (
  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0",       file:"Mshtml.dll", version:"8.0.6001.22903", min_version:"8.0.6001.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0",       file:"Mshtml.dll", version:"8.0.6001.18813", min_version:"8.0.0.0",        dir:"\system32") ||

  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.22180", min_version:"7.0.6002.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.18071", min_version:"7.0.0.0",        dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Mshtml.dll", version:"7.0.6001.22475", min_version:"7.0.6001.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Mshtml.dll", version:"7.0.6001.18294", min_version:"7.0.0.0",        dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.21089", min_version:"7.0.6000.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.16890", min_version:"7.0.0.0",        dir:"\system32") ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"8.0.6001.22902", min_version:"8.0.6001.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"8.0.6001.18812", min_version:"8.0.0.0",        dir:"\system32") ||

  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"7.0.6000.21089", min_version:"7.0.6000.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"7.0.6000.16890", min_version:"7.0.0.0",        dir:"\system32") ||

  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"6.0.3790.4555",  min_version:"6.0.0.0",        dir:"\system32") ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Mshtml.dll", version:"8.0.6001.22902", min_version:"8.0.6001.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Mshtml.dll", version:"8.0.6001.18812", min_version:"8.0.0.0",        dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Mshtml.dll", version:"8.0.6001.22902", min_version:"8.0.6001.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Mshtml.dll", version:"8.0.6001.18812", min_version:"8.0.0.0",        dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Mshtml.dll", version:"8.0.6001.22902", min_version:"8.0.6001.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Mshtml.dll", version:"8.0.6001.18812", min_version:"8.0.0.0",        dir:"\system32") ||

  hotfix_is_vulnerable(os:"5.1", sp:3,             file:"Mshtml.dll", version:"7.0.6000.21089", min_version:"7.0.6000.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:3,             file:"Mshtml.dll", version:"7.0.6000.16890", min_version:"7.0.0.0",        dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Mshtml.dll", version:"7.0.6000.21089", min_version:"7.0.6000.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Mshtml.dll", version:"7.0.6000.16890", min_version:"7.0.0.0",        dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Mshtml.dll", version:"7.0.6000.21089", min_version:"7.0.6000.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Mshtml.dll", version:"7.0.6000.16890", min_version:"7.0.0.0",        dir:"\system32") ||

  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Mshtml.dll", version:"6.0.2900.5848",  min_version:"6.0.0.0",        dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Mshtml.dll", version:"6.0.3790.4555",  min_version:"6.0.0.0",        dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Mshtml.dll", version:"6.0.2900.3603",  min_version:"6.0.0.0",        dir:"\system32") ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0", file:"Msrating.dll", version:"6.0.2800.1982", min_version:"6.0.0.0", dir:"\system32") ||

  hotfix_is_vulnerable(os:"5.0", file:"Mshtml.dll",   version:"5.0.3879.2200", min_version:"5.0.0.0", dir:"\system32")
)
{
  set_kb_item(name:"SMB/Missing/MS09-034", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end(); 
  exit(0, "The host is not affected");
}
