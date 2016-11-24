#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42109);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-2521", "CVE-2009-3023");
  script_bugtraq_id(36273, 36189);
  script_xref(name:"OSVDB", value:"57589");
  script_xref(name:"OSVDB", value:"57753");

  script_name(english:"MS09-053: Vulnerabilities in FTP Service for Internet Information Services Could Allow Remote Code Execution (975254)");
  script_summary(english:"Checks version of ftpsvc2.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FTP server is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host has a version of IIS whose FTP service is affected by\n",
      "one or both of the following vulnerabilities :\n",
      "\n",
      "  - By sending specially crafted list commands to the\n",
      "    remote Microsoft FTP service, an attacker is able\n",
      "    to cause the service to become unresponsive. \n",
      "    (CVE-2009-2521)\n",
      "\n",
      "  - A flaw in the way the installed Microsoft FTP service\n",
      "    in IIS handles list commands can be exploited to\n",
      "    execute remote commands in the context of the\n",
      "    LocalSystem account with IIS 5.0 under Windows 2000 or\n",
      "    to cause the FTP server to stop and become unresponsive\n",
      "    with IIS 5.1 under Windows XP or IIS 6.0 under Windows\n",
      "    2003. (CVE-2009-3023)"
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for IIS 5.0, 5.1, 6.0, and\n",
      "7.0 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-053.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/09/01"
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
if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");

if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:3) <= 0) exit(0, "The host is not affected based on its version / service pack.");
if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");



if (
  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"ftpsvc2.dll", version:"7.0.6002.22219", min_version:"7.0.6002.22000", dir:"\System32\inetsrv") ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"ftpsvc2.dll", version:"7.0.6002.18107",                               dir:"\System32\inetsrv") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"ftpsvc2.dll", version:"7.0.6001.22516", min_version:"7.0.6001.22000", dir:"\System32\inetsrv") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"ftpsvc2.dll", version:"7.0.6001.18327",                               dir:"\System32\inetsrv") ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"ftpsvc2.dll", version:"7.0.6000.21123", min_version:"7.0.6000.20000", dir:"\System32\inetsrv") ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"ftpsvc2.dll", version:"7.0.6000.16923",                               dir:"\System32\inetsrv") ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"ftpsvc2.dll", version:"6.0.3790.4584",                                dir:"\System32\inetsrv") ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"ftpsvc2.dll", version:"6.0.2600.5875",                                dir:"\System32\inetsrv") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"ftpsvc2.dll", version:"6.0.3790.4584",                                dir:"\System32\inetsrv") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"ftpsvc2.dll", version:"6.0.2600.3624",                                dir:"\System32\inetsrv") ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0",                   file:"ftpsvc2.dll", version:"5.0.2195.7336",                                dir:"\System32\inetsrv")
)
{
  set_kb_item(name:"SMB/Missing/MS09-053", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end(); 
  exit(0);
}
else
{
  hotfix_check_fversion_end(); 
  exit(0, "The host is not affected.");
}
