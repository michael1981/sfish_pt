#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39343);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-0549", "CVE-2009-0557", "CVE-2009-0558", "CVE-2009-0559",
                "CVE-2009-0560", "CVE-2009-0561", "CVE-2009-1134");
  script_bugtraq_id(35215, 35241, 35242, 35243, 35244, 35245, 35246);
  script_xref(name:"OSVDB", value:"54952");
  script_xref(name:"OSVDB", value:"54953");
  script_xref(name:"OSVDB", value:"54954");
  script_xref(name:"OSVDB", value:"54955");
  script_xref(name:"OSVDB", value:"54956");
  script_xref(name:"OSVDB", value:"54957");
  script_xref(name:"OSVDB", value:"54958");

  script_name(english:"MS09-021: Vulnerabilities in Microsoft Office Excel Could Allow Remote Code Execution (969462)");
  script_summary(english:"Checks version of Excel.exe / Xlview.exe / Excelcnv.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "It is possible to execute arbitrary code on the remote Windows host\n",
      "using Microsoft Excel."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host contains a version of Microsoft Excel / Excel Viewer /\n",
      "2007 Microsoft Office system or the Microsoft Office Compatibility\n",
      "Pack that is affected by several buffer overflow and memory corruption\n",
      "vulnerabilities.  If an attacker can trick a user on the affected host\n",
      "into opening a specially crafted Excel file, he may be able to\n",
      "leverage either of these issues to run arbitrary code on the host\n",
      "subject to the user's privileges."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Excel 2000, 2002, 2003,\n",
      "and 2007, Excel Viewer and Excel Viewer 2003 as well as the 2007\n",
      "Microsoft Office system and the Microsoft Office Compatibility Pack :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-021.mspx"
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
      ver[2] < 6504 ||
      (ver[2] == 6504 && ver[3] < 5001)
    )
  )
  {
    info = string(
      "  Product           : Excel 2007\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 12.0.6504.5001\n"
    );
  }  
  # Excel 2003.
  else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8307)
  {
    info = string(
      "  Product           : Excel 2003\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 11.0.8307.0\n"
    );
  }
  # Excel 2002.
  else if (ver[0] == 10 && ver[1] == 0 && ver[2] < 6854)
  {
    info = string(
      "  Product           : Excel 2002\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 10.0.6854.0\n"
    );
  }
  # Excel 2000.
  else if (ver[0] == 9 && ver[1] == 0 && ver[2] == 0 && ver[3] < 8979)
  {
    info = string(
      "  Product           : Excel 2000\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 9.0.0.8979\n"
    );
  }

  if (info)
  {
    set_kb_item(name:"SMB/Missing/MS09-021", value:TRUE);

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
      ver[2] < 6504 ||
      (ver[2] == 6504 && ver[3] < 5000)
    )
  )
  {
    info = string(
      "  Product           : Excel Viewer\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 12.0.6504.5000\n"
    );
  }  
  # Excel Viewer 2003.
  else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8307)
  {
    info = string(
      "  Product           : Excel 2003\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 11.0.8307.0\n"
    );
  }

  if (info)
  {
    set_kb_item(name:"SMB/Missing/MS09-021", value:TRUE);

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
      ver[2] < 6504 ||
      (ver[2] == 6504 && ver[3] < 5001)
    )
  )
  {
    info = string(
      "  Product           : 2007 Office system and the Office Compatibility Pack\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 12.0.6504.5001\n"
    );
  }  

  if (info)
  {
    set_kb_item(name:"SMB/Missing/MS09-021", value:TRUE);

    hotfix_add_report(info);
    hotfix_security_hole();
    exit(0);
  }
}
