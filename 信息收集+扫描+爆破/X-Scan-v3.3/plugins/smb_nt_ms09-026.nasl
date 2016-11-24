#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39348);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-0568");
  script_bugtraq_id(35219);
  script_xref(name:"OSVDB", value:"54936");

  script_name(english:"MS09-026: Vulnerability in RPC Could Allow Elevation of Privilege (970238)");
  script_summary(english:"Checks file version of Rpcrt4.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "Arbitrary code can be executed on the remote host through its RPC\n",
      "facility."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The RPC Marshalling Engine installed on the remote Windows host does\n",
      "not update its internal state appropriately, which could lead to a\n",
      "pointer being read from an incorrect location.  A remote attacker may\n",
      "be able to leverage this issue to execute arbitrary code on the\n",
      "affected host and take complete control of it."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Windows 2000, XP, 2003,\n",
      "Vista and 2008 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-026.mspx"
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


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:3) <= 0) exit(0);

if (is_accessible_share())
{
  if (
    # Vista / Windows Server 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Rpcrt4.dll", version:"6.0.6002.22120", min_version:"6.0.6002.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Rpcrt4.dll", version:"6.0.6002.18024",                               dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Rpcrt4.dll", version:"6.0.6001.22417", min_version:"6.0.6001.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Rpcrt4.dll", version:"6.0.6001.18247",                               dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Rpcrt4.dll", version:"6.0.6000.21045", min_version:"6.0.6000.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Rpcrt4.dll", version:"6.0.6000.16850",                               dir:"\system32") ||

    # Windows 2003
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Rpcrt4.dll", version:"5.2.3790.4502", dir:"\system32") ||

    # Windows XP
    hotfix_is_vulnerable(os:"5.1", sp:3, file:"Rpcrt4.dll", version:"5.1.2600.5795", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.1", sp:2, file:"Rpcrt4.dll", version:"5.1.2600.3555", dir:"\system32") ||

    # Windows 2000
    hotfix_is_vulnerable(os:"5.0", file:"Rpcrt4.dll", version:"5.0.2195.7281", dir:"\system32")
  )
  {
    set_kb_item(name:"SMB/Missing/MS09-026", value:TRUE);
    hotfix_security_hole();
  }

  hotfix_check_fversion_end();
}
