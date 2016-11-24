#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42441);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-3127", "CVE-2009-3128", "CVE-2009-3129", "CVE-2009-3130",
                "CVE-2009-3131", "CVE-2009-3132", "CVE-2009-3133", "CVE-2009-3134");
  script_bugtraq_id(36908, 36909, 36911, 36912, 36943, 36944, 36945, 36946);
  script_xref(name:"OSVDB", value:"59858");
  script_xref(name:"OSVDB", value:"59859");
  script_xref(name:"OSVDB", value:"59860");
  script_xref(name:"OSVDB", value:"59861");
  script_xref(name:"OSVDB", value:"59862");
  script_xref(name:"OSVDB", value:"59863");
  script_xref(name:"OSVDB", value:"59864");
  script_xref(name:"OSVDB", value:"59866");

  script_name(english:"MS09-067: Vulnerabilities in Microsoft Office Excel Could Allow Remote Code Execution (972652)");
  script_summary(english:"Checks the version of all affected Excel renderers");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through opening a
Microsoft Excel file."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host contains a version of Microsoft Excel, Excel Viewer,
2007 Microsoft Office system, or Microsoft Office Compatibility Pack
that is affected by several memory corruption vulnerabilities.  An
attacker could exploit this by tricking a user into opening a
maliciously crafted Excel file, resulting in the execution of
arbitrary code subject to the user's privileges."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Office XP, Office 2003,
Office 2007, and Office Excel Viewer :

http://www.microsoft.com/technet/security/bulletin/MS09-067.mspx"
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/11/10"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/11/10"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/11/10"
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

# Excel.
version = get_kb_item("SMB/Office/Excel/Version");
if (version)
{
  path = get_kb_item("SMB/Office/Excel/ProductPath");
  if (isnull(path)) path = "n/a";

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Excel 2007.
  if (
    ver[0] == 12 && ver[1] == 0 &&
    (
      ver[2] < 6514 ||
      (ver[2] == 6514 && ver[3] < 5000)
    )
  )
  {
    info = string(
      "  Product           : Excel 2007\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 12.0.6514.5000\n"
    );
  }
  # Excel 2003.
  else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8316)
  {
    info = string(
      "  Product           : Excel 2003\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 11.0.8316.0\n"
    );
  }
  # Excel 2002.
  else if (ver[0] == 10 && ver[1] == 0 && ver[2] < 6856)
  {
    info = string(
      "  Product           : Excel 2002\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 10.0.6856.0\n"
    );
  }

  if (info)
  {
    set_kb_item(name:"SMB/Missing/MS09-067", value:TRUE);

    hotfix_add_report(info);
    hotfix_security_hole();
    exit(0);
  }
}


# Excel Viewer.
version = get_kb_item("SMB/Office/ExcelViewer/Version");
if (version)
{
  path = get_kb_item("SMB/Office/ExcelViewer/ProductPath");
  if (isnull(path)) path = "n/a";

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Excel Viewer.
  if (
    ver[0] == 12 && ver[1] == 0 &&
    (
      ver[2] < 6514 ||
      (ver[2] == 6514 && ver[3] < 5000)
    )
  )
  {
    info = string(
      "  Product           : Excel Viewer\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 12.0.6514.5000\n"
    );
  }
  # Excel Viewer 2003.
  else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8313)
  {
    info = string(
      "  Product           : Excel 2003\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 11.0.8313.0\n"
    );
  }

  if (info)
  {
    set_kb_item(name:"SMB/Missing/MS09-067", value:TRUE);

    hotfix_add_report(info);
    hotfix_security_hole();
    exit(0);
  }
}


# 2007 Microsoft Office system and the Microsoft Office Compatibility Pack.
version = get_kb_item("SMB/Office/ExcelCnv/Version");
if (version)
{
  path = get_kb_item("SMB/Office/ExcelCnv/ProductPath");
  if (isnull(path)) path = "n/a";

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # 2007 Office system and the Office Compatibility Pack.
  if (
    ver[0] == 12 && ver[1] == 0 &&
    (
      ver[2] < 6514 ||
      (ver[2] == 6514 && ver[3] < 5000)
    )
  )
  {
    info = string(
      "  Product           : 2007 Office system and the Office Compatibility Pack\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 12.0.6514.5000\n"
    );
  }

  if (info)
  {
    set_kb_item(name:"SMB/Missing/MS09-067", value:TRUE);

    hotfix_add_report(info);
    hotfix_security_hole();
    exit(0);
  }
}

