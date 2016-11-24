#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40892);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-1132");
  script_bugtraq_id(36223);
  script_xref(name:"OSVDB", value:"57806");

  script_name(english:"MS09-049: Vulnerability in Wireless LAN AutoConfig Service Could Allow Remote Code Execution (970710)");
  script_summary(english:"Checks version of Wlansvc.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
       "Arbitrary code can be executed on the remote host through the Wireless\n",
       "LAN AutoConfig Service."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "A remote code execution vulnerability exists in the way that the\n",
      "Wireless LAN AutoConfig Service (wlansvc) parses specific frames\n",
      "received on the wireless network.  This vulnerability could allow\n",
      "remote code execution if a client or server with a wireless network\n",
      "interface enabled receives specially crafted wireless frames.  If a\n",
      "user is logged on with administrative user rights, an attacker who\n",
      "successfully exploited this vulnerability could take complete control\n",
      "of an affected system."
    )
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Microsoft has released a set of patches for Windows Vista and 2008 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-049.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C"
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
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");

if (hotfix_check_sp(vista:3) <= 0) exit(0, "The host is not affected based on its version / service pack.");
if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");


if (
  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Wlansvc.dll", version:"6.0.6002.22170", min_version:"6.0.6002.20000", dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Wlansvc.dll", version:"6.0.6002.18064",                               dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Wlansvc.dll", version:"6.0.6001.22468", min_version:"6.0.6001.20000", dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Wlansvc.dll", version:"6.0.6001.18288",                               dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Wlansvc.dll", version:"6.0.6000.21082", min_version:"6.0.6000.20000", dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Wlansvc.dll", version:"6.0.6000.16884",                               dir:"\System32")
)
{
  set_kb_item(name:"SMB/Missing/MS09-049", value:TRUE);
  hotfix_security_warning();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected.");
}
