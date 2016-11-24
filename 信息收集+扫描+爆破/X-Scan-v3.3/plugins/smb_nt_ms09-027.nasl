#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39349);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-0563", "CVE-2009-0565");
  script_bugtraq_id(35188, 35190);
  script_xref(name:"OSVDB", value:"54959");
  script_xref(name:"OSVDB", value:"54960");

  script_name(english:"MS09-027: Vulnerabilities in Microsoft Office Word Could Allow Remote Code Execution (969514)");
  script_summary(english:"Checks version of Word");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "Arbitrary code can be executed on the remote host through Microsoft\n",
      "Word."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote Windows host is running a version of Microsoft Word or Word\n",
      "Viewer that is affected by two buffer overflow vulnerabilities.  If an\n",
      "attacker can trick a user on the affected host into opening a\n",
      "specially crafted Word file, he could leverage these issues to execute\n",
      "arbitrary code subject to the user's privileges."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Word 2000, 2002, 2003 and\n",
      "Word 2007, Word Viewer and Word Viewer 2003 as well as the 2007\n",
      "Microsoft Office system and the Microsoft Office Compatibility Pack :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-027.mspx"
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
 
  script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_hotfixes_fcheck.inc");


info = "";

# Word.
version = get_kb_item("SMB/Office/Word/Version");
if (version)
{
  path = get_kb_item("SMB/Office/Word/ProductPath");
  if (isnull(path)) path = "n/a";

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Word 2007.
  if (
    ver[0] == 12 && ver[1] == 0 &&
    (
      ver[2] < 6504 ||
      (ver[2] == 6504 && ver[3] < 5000)
    )
  )
  {
    info = string(
      "  Product           : Word 2007\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 12.0.6504.5000\n"
    );
  }  
  # Word 2003.
  else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8307)
  {
    info = string(
      "  Product           : Word 2003\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 11.0.8307.0\n"
    );
  }
  # Word 2002.
  else if (ver[0] == 10 && ver[1] == 0 && ver[2] < 6854)
  {
    info = string(
      "  Product           : Word 2002\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 10.0.6854.0\n"
    );
  }
  # Word 2000.
  else if (ver[0] == 9 && ver[1] == 0 && ver[2] == 0 && ver[3] < 8979)
  {
    info = string(
      "  Product           : Word 2000\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 9.0.0.8979\n"
    );
  }

  if (info)
  {
    set_kb_item(name:"SMB/Missing/MS09-027", value:TRUE);

    hotfix_add_report(info);
    hotfix_security_hole();
    exit(0);
  }
}


# Word Viewer.
version = get_kb_item("SMB/Office/WordViewer/Version");
if (version)
{
  path = get_kb_item("SMB/Office/WordViewer/ProductPath");
  if (isnull(path)) path = "n/a";

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Word Viewer 2003.
  if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8307)
  {
    info = string(
      "  Product           : Word Viewer / Word Viewer 2003\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 11.0.8307.0\n"
    );
  }

  if (info)
  {
    set_kb_item(name:"SMB/Missing/MS09-027", value:TRUE);

    hotfix_add_report(info);
    hotfix_security_hole();
    exit(0);
  }
}


# 2007 Microsoft Office system and the Microsoft Office Compatibility Pack.
version = get_kb_item("SMB/Office/WordCnv/Version");
if (version)
{
  path = get_kb_item("SMB/Office/WordCnv/ProductPath");
  if (isnull(path)) path = "n/a";

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # 2007 Office system and the Office Compatibility Pack.
  if (
    ver[0] == 12 && ver[1] == 0 &&
    (
      ver[2] < 6500 ||
      (ver[2] == 6500 && ver[3] < 5000)
    )
  )
  {
    info = string(
      "  Product           : 2007 Office system and the Office Compatibility Pack\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 12.0.6500.5000\n"
    );
  }  

  if (info)
  {
    set_kb_item(name:"SMB/Missing/MS09-027", value:TRUE);

    hotfix_add_report(info);
    hotfix_security_hole();
    exit(0);
  }
}
