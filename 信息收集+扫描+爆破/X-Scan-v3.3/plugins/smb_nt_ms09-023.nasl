#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39345);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-0239");
  script_bugtraq_id(35220);
  script_xref(name:"OSVDB", value:"54935");

  script_name(english:"MS09-023: Vulnerability in Windows Search Could Allow Information Disclosure (963093)");
  script_summary(english:"Checks version of Mssph.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "A vulnerability in Windows Search may lead to information disclosure."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote Windows host contains a version of Windows Search that has\n",
      "a flaw in the way it uses MSHTML (a.k.a.  Trident) to render HTML\n",
      "content that could result in information disclosure.  If an attacker\n",
      "can trick a user on the affected host into putting a specially crafted\n",
      "HTML file on the system or in an indexed mail box and get the user to\n",
      "perform a specific search, he may be able to leverage the issue to\n",
      "disclose information, forward user data to a third party, or access\n",
      "any data on the affected systems that was accessible to the logged-on\n",
      "user."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Windows XP and 2003 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-023.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N"
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


if (hotfix_check_sp(xp:4, win2003:3) <= 0) exit(0);

if (is_accessible_share())
{
  if (
    # Windows 2003
    hotfix_is_vulnerable(os:"5.2", file:"Mssph.dll", version:"7.0.6001.18260", dir:"\system32") ||

    # Windows XP
    hotfix_is_vulnerable(os:"5.1", file:"Mssph.dll", version:"7.0.6001.18260", dir:"\system32")
  )
  {
    set_kb_item(name:"SMB/Missing/MS09-023", value:TRUE);
    hotfix_security_warning();
  }

  hotfix_check_fversion_end(); 
  exit(0);
}
