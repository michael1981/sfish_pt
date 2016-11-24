#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39793);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-0566");
  script_bugtraq_id(35599);
  script_xref(name:"OSVDB", value:"55838");

  script_name(english:"MS09-030: Vulnerability in Microsoft Office Publisher Could Allow Remote Code Execution (969516)");
  script_summary(english:"Checks versions of Mspub.exe and associated DLLs");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "It is possible to execute arbitrary code on the remote Windows host\n",
      "using Microsoft Office Publisher."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote Windows host contains a version of Microsoft Office\n",
      "Publisher that fails to properly calculate object handler data when\n",
      "opening, importing, or converting files created in versions older\n",
      "than Microsoft Office Publisher 2007, which could lead to memory\n",
      "corruption.\n",
      "\n",
      "If an attacker can trick a user on the affected system into opening a\n",
      "specially crafted Publisher file with Microsoft Office Publisher, he\n",
      "may be able to leverage this issue to execute arbitrary code subject\n",
      "to the user's privileges."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a patch for Publisher 2007 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-030.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/07/14"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/07/14"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/07/14"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 
  script_dependencies("smb_nt_ms02-031.nasl");
  script_require_keys("SMB/Office/Publisher/Version");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


version = get_kb_item("SMB/Office/Publisher/Version");
if (!version) exit(0, "No version information for Publisher available in the KB.");
if (!ereg(pattern:"^12\..*", string:version)) exit(0, "A version of Publisher other than 2007 is installed and hence not affected.");


# Publisher 2007 - fixed in 12.0.6501.5000
middle =  ereg_replace(pattern:"^12\.0\.([0-9]*)\.[0-9]*$", string:version, replace:"\1");
if (middle != version && int(middle) < 6501)
{
  set_kb_item(name:"SMB/Missing/MS09-030", value:TRUE);

  path = get_kb_item("SMB/Office/Publisher/ProductPath");
  if (isnull(path)) path = "n/a";

  info = string(
    "  Product           : Publisher 2007\n",
    "  Path              : ", path, "\n",
    "  Installed version : ", version, "\n",
    "  Fix               : 12.0.6501.5000\n"
  );
  hotfix_add_report(info);
  hotfix_security_hole();

  hotfix_check_fversion_end(); 
  exit(0);
}


programfiles = hotfix_get_officeprogramfilesdir();
if (!programfiles) exit(1, "Can't determine Office program files directory.");
share = ereg_replace(pattern:"(^[A-Za-z]):.*", replace:"\1$", string:programfiles);
if (!is_accessible_share(share:share)) exit(1, "Can't access '"+share+"' share.");

path = programfiles + "\Microsoft Office\Office12";
if (
  hotfix_check_fversion(file:"Morph9.dll",  path:path, version:"12.0.6500.5000") == HCF_OLDER ||
  hotfix_check_fversion(file:"Prtf9.dll",   path:path, version:"12.0.6500.5000") == HCF_OLDER ||
  hotfix_check_fversion(file:"Ptxt9.dll",   path:path, version:"12.0.6500.5000") == HCF_OLDER ||
  hotfix_check_fversion(file:"Pubconv.dll", path:path, version:"12.0.6501.5000") == HCF_OLDER ||
  hotfix_check_fversion(file:"Pubtrap.dll", path:path, version:"12.0.6500.5000") == HCF_OLDER 
)
{
  set_kb_item(name:"SMB/Missing/MS09-030", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end(); 
  exit(0);
}
else
{
  hotfix_check_fversion_end(); 
  exit(0, "The host is not affected.");
}
