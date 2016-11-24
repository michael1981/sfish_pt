#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42110);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-1547", "CVE-2009-2529", "CVE-2009-2530", "CVE-2009-2531");
  script_bugtraq_id(36616, 36620, 36621, 36622);
  script_xref(name:"OSVDB", value:"58871");
  script_xref(name:"OSVDB", value:"58872");
  script_xref(name:"OSVDB", value:"58873");
  script_xref(name:"OSVDB", value:"58874");

  script_name(english:"MS09-054: Cumulative Security Update for Internet Explorer (974455)");
  script_summary(english:"Checks version of mshtml.dll");

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
      "The remote host is missing IE Security Update 974455.\n",
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
      "http://www.microsoft.com/technet/security/Bulletin/MS09-054.mspx"
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


if (!get_kb_item("SMB/WindowsVersion")) exit(1, "The 'SMB/WindowsVersion' KB item is missing.");
if (hotfix_check_server_core() == 1) exit(0, "Windows Server Core installs are not affected.");
if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:3, win7:1) <= 0) exit(0, "The host is not affected based on its version / service pack.");

if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

if (
  # Windows 7
  hotfix_is_vulnerable(os:"6.1",       file:"Mshtml.dll", version:"8.0.7600.16419", min_version:"8.0.7600.16000", dir:"\system32") ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0",       file:"Mshtml.dll", version:"8.0.6001.22918", min_version:"8.0.6001.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0",       file:"Mshtml.dll", version:"8.0.6001.18828", min_version:"8.0.0.0",        dir:"\system32") ||

  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.22212", min_version:"7.0.6002.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.18100", min_version:"7.0.0.0",        dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Mshtml.dll", version:"7.0.6001.22508", min_version:"7.0.6001.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Mshtml.dll", version:"7.0.6001.18319", min_version:"7.0.0.0",        dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.21116", min_version:"7.0.6000.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.16916", min_version:"7.0.0.0",        dir:"\system32") ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"8.0.6001.22918", min_version:"8.0.6001.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"8.0.6001.18828", min_version:"8.0.0.0",        dir:"\system32") ||

  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"7.0.6000.21115", min_version:"7.0.6000.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"7.0.6000.16915", min_version:"7.0.0.0",        dir:"\system32") ||

  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"6.0.3790.4589",  min_version:"6.0.0.0",        dir:"\system32") ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Mshtml.dll", version:"8.0.6001.22918", min_version:"8.0.6001.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Mshtml.dll", version:"8.0.6001.18828", min_version:"8.0.0.0",        dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Mshtml.dll", version:"8.0.6001.22918", min_version:"8.0.6001.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Mshtml.dll", version:"8.0.6001.18828", min_version:"8.0.0.0",        dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Mshtml.dll", version:"8.0.6001.22918", min_version:"8.0.6001.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Mshtml.dll", version:"8.0.6001.18828", min_version:"8.0.0.0",        dir:"\system32") ||

  hotfix_is_vulnerable(os:"5.1", sp:3,             file:"Mshtml.dll", version:"7.0.6000.21115", min_version:"7.0.6000.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:3,             file:"Mshtml.dll", version:"7.0.6000.16915", min_version:"7.0.0.0",        dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Mshtml.dll", version:"7.0.6000.21115", min_version:"7.0.6000.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Mshtml.dll", version:"7.0.6000.16915", min_version:"7.0.0.0",        dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Mshtml.dll", version:"7.0.6000.21115", min_version:"7.0.6000.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Mshtml.dll", version:"7.0.6000.16915", min_version:"7.0.0.0",        dir:"\system32") ||

  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Mshtml.dll", version:"6.0.2900.5880",  min_version:"6.0.0.0",        dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Mshtml.dll", version:"6.0.3790.4589",  min_version:"6.0.0.0",        dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Mshtml.dll", version:"6.0.2900.3627",  min_version:"6.0.0.0",        dir:"\system32") ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0", file:"Mshtml.dll",   version:"6.0.2800.1638", min_version:"6.0.0.0", dir:"\system32") ||

  hotfix_is_vulnerable(os:"5.0", file:"Mshtml.dll",   version:"5.0.3881.100",  min_version:"5.0.0.0", dir:"\system32")

)
{
  set_kb_item(name:"SMB/Missing/MS09-054", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected");
}

