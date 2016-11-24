#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36147);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-0100", "CVE-2009-0238");
  script_bugtraq_id(33870, 34413);
  script_xref(name:"OSVDB", value:"52695");
  script_xref(name:"OSVDB", value:"53665");

  script_name(english: "MS09-009: Vulnerabilities in Microsoft Office Excel Could Cause Remote Code Execution (968557)");
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
      "2007 Microsoft Office system and the Microsoft Office Compatibility\n",
      "Pack that is affected by two memory corruption vulnerabilities.  If an\n",
      "attacker can trick a user on the affected host into opening a\n",
      "specially crafted Excel file, he may be able to leverage either of\n",
      "these issues to run arbitrary code on the host subject to the user's\n",
      "privileges."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Excel 2000, 2002, 2003,\n",
      "and 2007, Excel Viewer and Excel Viewer 2003 as well as the 2007\n",
      "Microsoft Office system and the Microsoft Office Compatibility Pack :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-009.mspx"
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


# Excel
version = get_kb_item("SMB/Office/Excel/Version");
if (version)
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (
    # Excel 2007 - fixed in 12.0.6341.5001
    (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6341 ||
        (ver[2] == 6341 && ver[3] < 5001)
      )
    ) ||

    # Excel 2003 - fixed in 11.0.8302.0
    (ver[0] == 11 && ver[1] == 0 && ver[2] < 8302) ||

    # Excel 2002 - fixed in 10.0.6852.0
    (ver[0] == 10 && ver[1] == 0 && ver[2] < 6852) ||

    # Excel 2000 - fixed in 9.0.0.8977
    (ver[0] == 9 && ver[1] == 0 && ver[2] == 0 && ver[3] < 8977)

  )
  {
 {
 set_kb_item(name:"SMB/Missing/MS09-009", value:TRUE);
 hotfix_security_hole();
 }
    exit(0);
  }
}


# Excel Viewer
version = get_kb_item("SMB/Office/ExcelViewer/Version");
if (version)
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (
    # Excel - fixed in 12.0.6341.5001
    (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6341 ||
        (ver[2] == 6341 && ver[3] < 5001)
      )
    ) ||

    # Excel Viewer 2003 - fixed in 11.0.8302.0
    (ver[0] == 11 && ver[1] == 0 && ver[2] < 8302)
  )
  {
 {
 set_kb_item(name:"SMB/Missing/MS09-009", value:TRUE);
 hotfix_security_hole();
 }
    exit(0);
  }
}


# 2007 Microsoft Office system and the Microsoft Office Compatibility Pack
version = get_kb_item("SMB/Office/ExcelCnv/Version");
if (version)
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (
    # fixed in 12.0.6341.5001
    ver[0] == 12 && ver[1] == 0 &&
    (
      ver[2] < 6341 ||
      (ver[2] == 6341 && ver[3] < 5001)
    )
  )
  {
 {
 set_kb_item(name:"SMB/Missing/MS09-009", value:TRUE);
 hotfix_security_hole();
 }
    exit(0);
  }
}
