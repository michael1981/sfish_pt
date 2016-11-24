#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42112);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2009-2510", "CVE-2009-2511");
  script_bugtraq_id(36475, 36577);
  script_xref(name:"OSVDB", value:"58855");
  script_xref(name:"OSVDB", value:"58856");

  script_name(english:"MS09-056: Vulnerabilities in Windows CryptoAPI Could Allow Spoofing (974571)");
  script_summary(english:"Checks version of msasn1.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "Certain identity validation methods may be bypassed allowing impersonation."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote Windows host contains a version of the Microsoft Windows CryptoAPI\n",
      "that is affected by multiple vulnerabilities :\n",
      "\n",
      "  - A spoofing vulnerability exists in the Microsoft Windows\n",
      "    CryptoAPI component when parsing ASN.1 information from\n",
      "    X.509 certificates. An attacker who successfully\n",
      "    exploited this vulnerability could impersonate another\n",
      "    user or system. (CVE-2009-2510)\n",
      "\n",
      "  - A spoofing vulnerability exists in the Microsoft Windows\n",
      "    CryptoAPI component when parsing ASN.1 object\n",
      "    identifiers from X.509 certificates. An attacker who\n",
      "    successfully exploited this vulnerability could\n",
      "    impersonate another user or system. (CVE-2009-2511)"
    )
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Microsoft has released a set of patches for Windows 2000, XP, 2003,\n",
      "Vista, 2008 and Windows 7 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/bulletin/MS09-056.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
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

if ( !get_kb_item("SMB/WindowsVersion") )
  exit(1, "The 'SMB/WindowsVersion' KB item is missing.");
if ( hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:3, win7:1) <= 0 )
  exit(0, "The host is not affected based on its version / service pack.");
if ( !is_accessible_share() )
  exit(1, "is_accessible_share() failed.");

if (
  # Windows 7
  hotfix_is_vulnerable(os:"6.1", sp:0,  file:"msasn1.dll", version:"6.1.7600.16415", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.1", sp:0,  file:"msasn1.dll", version:"6.1.7600.20518", min_version:"6.0.7600.20000", dir:"\system32") ||

  # Vista / 2k8
  hotfix_is_vulnerable(os:"6.0", sp:0,  file:"msasn1.dll", version:"6.0.6000.16922", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:0,  file:"msasn1.dll", version:"6.0.6000.21122", min_version:"6.0.6000.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,  file:"msasn1.dll", version:"6.0.6001.18326", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,  file:"msasn1.dll", version:"6.0.6001.22515", min_version:"6.0.6001.22000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:2,  file:"msasn1.dll", version:"6.0.6002.18106", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:2,  file:"msasn1.dll", version:"6.0.6002.22218", min_version:"6.0.6002.22000", dir:"\system32") ||

  # Windows 2003 x86 and x64
  hotfix_is_vulnerable(os:"5.2", file:"msasn1.dll", version:"5.2.3790.4584", min_version:"5.2.0.0", dir:"\system32") ||

  # Windows XP x64
  hotfix_is_vulnerable(os:"5.1", arch:"x64", file:"msasn1.dll", version:"5.2.3790.4584", min_version:"5.2.0.0", dir:"\system32") ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"msasn1.dll", version:"5.1.2600.3624", min_version:"5.1.0.0", dir:"\system32") ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"msasn1.dll", version:"5.1.2600.5875", min_version:"5.1.0.0", dir:"\system32") ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0", file:"msasn1.dll", version:"5.0.2195.7334", min_version:"5.0.0.0", dir:"\system32")

)
{
  set_kb_item(name:"SMB/Missing/MS09-056", value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected.");
}
