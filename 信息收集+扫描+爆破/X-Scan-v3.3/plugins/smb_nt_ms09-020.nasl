#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39342);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-1122", "CVE-2009-1535");
  script_bugtraq_id(34993);
  script_xref(name:"OSVDB", value:"54555");

  script_name(english:"MS09-020: Vulnerabilities in Internet Information Services (IIS) Could Allow Elevation of Privilege (970483)");
  script_summary(english:"Checks version of Httpext.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "It is possible to bypass authentication on the remote web server."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "Due to a flaw in the WebDAV extension for IIS, an anonymous remote\n",
      "attacker may be able to bypass authentication by sending a specially\n",
      "crafted HTTP request and gain access to a protected location."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Windows 2000, XP and 2003 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-020.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
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


if (hotfix_check_iis_installed() <= 0) exit(0);
if (hotfix_check_sp(win2k:6, xp:4, win2003:3) <= 0) exit(0);

if (is_accessible_share())
{
  if (
    # Windows 2003
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Httpext.dll", version:"6.0.3790.4518", dir:"\system32\inetsrv") ||

    # Windows XP
    hotfix_is_vulnerable(os:"5.1", sp:3, file:"Httpext.dll", version:"6.0.2600.5817", dir:"\system32\inetsrv") ||
    hotfix_is_vulnerable(os:"5.1", sp:2, file:"Httpext.dll", version:"6.0.2600.3574", dir:"\system32\inetsrv") ||

    # Windows 2000
    hotfix_is_vulnerable(os:"5.0", file:"Httpext.dll", version:"5.0.2195.7290", dir:"\system32\inetsrv")
  )
  {
    set_kb_item(name:"SMB/Missing/MS09-020", value:TRUE);
    hotfix_security_hole();
  }

  hotfix_check_fversion_end(); 
  exit(0);
}
