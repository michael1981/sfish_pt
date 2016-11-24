#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39346);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-1533");
  script_bugtraq_id(35184);
  script_xref(name:"OSVDB", value:"54939");

  script_name(english:"MS09-024: Vulnerability in Microsoft Works Converters Could Allow Remote Code Execution (957632)");
  script_summary(english:"Checks file version of the converters");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "Arbitrary code can be executed on the remote host through Microsoft\n",
      "Office."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running a version of Microsoft Works for Windows\n",
      "document converters that is affected by a buffer overflow\n",
      "vulnerability.  If an attacker can trick a user on the affected host\n",
      "into opening a specially crafted Works file, he may be able to\n",
      "leverage this issue to run arbitrary code on the host subject to the\n",
      "user's privileges."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Office 2000, 2003 and XP\n",
      "as well as 2007 Microsoft Office System, Works 8.5 and Works 9 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-024.mspx"
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


if (!is_accessible_share()) exit(0);  

commonfiles = hotfix_get_officecommonfilesdir();
if  (!commonfiles) exit(0);

path = commonfiles + "\Microsoft Shared\TextConv";

office_version = hotfix_check_office_version();
if (office_version)
{
  if (
    # Office 2007.
    (
      office_version == "12.0" &&
      hotfix_check_fversion(file:"Works632.cnv", version:"9.07.0613.0", path:path) == HCF_OLDER
    ) ||
    # Office 2003.
    (
      office_version == "11.0" &&
      (
        hotfix_check_fversion(file:"Wkcvqd01.dll", version:"9.8.1117.0", path:path) == HCF_OLDER ||
        hotfix_check_fversion(file:"Wkcvqr01.dll", version:"9.8.1117.0", path:path) == HCF_OLDER
      )
    ) ||
    # Office XP.
    (
      office_version == "10.0" &&
      hotfix_check_fversion(file:"Works432.cnv", version:"2008.9.808.0", path:path) == HCF_OLDER
    ) ||
    # Office 2000.
    (
      office_version == "9.0" && 
      hotfix_check_fversion(file:"Works432.cnv", version:"2008.9.808.0", path:path) == HCF_OLDER
    )
  )
  {
    set_kb_item(name:"SMB/Missing/MS09-024", value:TRUE);
    hotfix_security_hole();

    hotfix_check_fversion_end(); 
    exit(0);
  }
}

if (hotfix_check_works_installed())
{
  if (
    # Works 9.
    hotfix_check_fversion(file:"Wkcvqd01.dll", version:"9.8.1117.0", min_version:"9.0.0.0", path:path) == HCF_OLDER ||
    hotfix_check_fversion(file:"Wkcvqr01.dll", version:"9.8.1117.0", min_version:"9.0.0.0", path:path) == HCF_OLDER ||

    # Works 8.
    hotfix_check_fversion(file:"Wkcvqd01.dll", version:"8.7.216.0", min_version:"8.0.0.0", path:path) == HCF_OLDER ||
    hotfix_check_fversion(file:"Wkcvqr01.dll", version:"8.7.216.0", min_version:"8.0.0.0", path:path) == HCF_OLDER
  )
  {
    set_kb_item(name:"SMB/Missing/MS09-024", value:TRUE);
    hotfix_security_hole();

    hotfix_check_fversion_end(); 
    exit(0);
  }
}


hotfix_check_fversion_end(); 
exit(0);
