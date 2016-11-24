#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36148);
  script_version("$Revision: 1.6 $");

  script_cve_id(
    "CVE-2008-4841", 
    "CVE-2009-0087", 
    "CVE-2009-0088", 
    "CVE-2009-0235"
  );
  script_bugtraq_id(29769, 32718, 34469, 34470);
  script_xref(name:"OSVDB", value:"50567");
  script_xref(name:"OSVDB", value:"53662");
  script_xref(name:"OSVDB", value:"53663");
  script_xref(name:"OSVDB", value:"53664");

  script_name(english: "MS09-010: Vulnerabilities in WordPad and Office Text Converters Could Allow Remote Code Execution (960477)");
  script_summary(english:"Checks for the presence of update 960477");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "It is possible to execute arbitrary code on the remote Windows host\n",
      "using a text converter."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host contains a version of the Microsoft WordPad and/or\n",
      "Microsoft Office text converters that could allow remote code\n",
      "execution if a specially crafted file is opened."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Office 2000 and XP as well\n",
      "as the Office 2003 File Converter Pack :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-010.mspx"
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


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if (hotfix_check_sp(win2k:6, xp:3, win2003:3) <= 0) exit(0);

if (is_accessible_share())
{
  path = hotfix_get_programfilesdir() + "\Windows NT\Accessories";

  if (
    # Windows 2003
    hotfix_is_vulnerable(os:"5.2", file:"Mswrd8.wpc", version:"10.0.803.10", path:path) ||

    # Windows XP
    hotfix_is_vulnerable(os:"5.1", file:"Mswrd8.wpc", version:"10.0.803.10", path:path) ||

    # Windows 2000
    hotfix_is_vulnerable(os:"5.0", file:"Mswrd8.wpc", version:"10.0.803.10", path:path)
  ) {
 set_kb_item(name:"SMB/Missing/MS09-010", value:TRUE);
 hotfix_security_hole();
 }


 office_version = hotfix_check_office_version();
 if ( office_version == "10.0" || office_version == "9.0" )
 {
 path = hotfix_get_commonfilesdir() + "\Microsoft Shared\TextConv";
 if ( 
     hotfix_is_vulnerable(os:"5.2", file:"Msconv97.dll", version:"2003.1100.8202.0", path:path) ||
     hotfix_is_vulnerable(os:"5.1", file:"Msconv97.dll", version:"2003.1100.8202.0", path:path) ||
     hotfix_is_vulnerable(os:"5.0", file:"Msconv97.dll", version:"2003.1100.8202.0", path:path)  
  ) {
 set_kb_item(name:"SMB/Missing/MS09-010", value:TRUE);
 hotfix_security_hole();
 }
 }

 
 
  hotfix_check_fversion_end(); 
  exit(0);
}
