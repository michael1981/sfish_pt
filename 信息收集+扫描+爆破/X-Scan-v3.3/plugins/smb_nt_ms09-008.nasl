#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35824);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2009-0093", "CVE-2009-0094", "CVE-2009-0233", "CVE-2009-0234");
  script_bugtraq_id(33982, 33988, 33989, 34013);
  script_xref(name:"OSVDB", value:"52517");
  script_xref(name:"OSVDB", value:"52518");
  script_xref(name:"OSVDB", value:"52519");
  script_xref(name:"OSVDB", value:"52520");

  script_name(english: "MS09-008: Vulnerabilities in DNS and WINS Server Could Allow Spoofing (962238)");
  script_summary(english:"Determines the presence of update 962238");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is vulnerable to DNS and/or WINS spoofing attacks."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host has a Windows DNS server and/or a Windows WINS server\n",
      "installed.\n",
      "\n",
      "Multiple vulnerabilities in the way that Windows DNS servers cache and\n",
      "validate queries as well as the way that Windows DNS servers and\n",
      "Windows WINS servers handle WPAD and ISATAP registration may allow\n",
      "remote attackers to redirect network traffic intended for systems on\n",
      "the Internet to the attacker's own systems."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Windows 2000, 2003 and\n",
      "2008 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-008.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N"
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


if (hotfix_check_sp(win2k:6, win2003:3, vista:2) <= 0) exit(0);
if ( ! get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/DNS/DisplayName") ) exit(0);



if (is_accessible_share())
{
  if (
    # Windows Server 2008
    #
    # nb: CVE-2009-0094 (WPAD WINS Server Registration Vulnerability) doesn't apply to 2008.
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Dns.exe", version:"6.0.6001.22375", min_version:"6.0.6001.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Dns.exe", version:"6.0.6001.18214", dir:"\system32") ||

    # Windows Server 2003
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Dns.exe", version:"5.2.3790.4460", dir:"\System32") ||
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Wins.exe", version:"5.2.3790.4446", dir:"\System32") ||
    hotfix_is_vulnerable(os:"5.2", sp:1, file:"Dns.exe", version:"5.2.3790.3295", dir:"\System32") ||
    hotfix_is_vulnerable(os:"5.2", sp:1, file:"Wins.exe", version:"5.2.3790.3281", dir:"\System32") ||

    # Windows 2000
    hotfix_is_vulnerable(os:"5.0", file:"Dns.exe", version:"5.0.2195.7260", dir:"\System32") ||
    hotfix_is_vulnerable(os:"5.0", file:"Wins.exe", version:"5.0.2195.7241", dir:"\System32")
  ) {
    set_kb_item(name:"SMB/Missing/MS09-008", value:TRUE);
    hotfix_security_warning();
 }
 
  hotfix_check_fversion_end(); 
}
