#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42442);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-3135");
  script_bugtraq_id(36950);
  script_xref(name:"OSVDB", value:"59857");

  script_name(english:"MS09-068: Vulnerability in Microsoft Office Word Could Allow Remote Code Execution (976307)");
  script_summary(english:"Checks version of Word");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through Microsoft
Word."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Windows host is running a version of Microsoft Word or
Word Viewer that is affected by a memory corruption vulnerability.  If
an attacker can trick a user on the affected host into opening a
specially crafted Word file, he could leverage this issue to execute
arbitrary code subject to the user's privileges."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Microsoft has released a set of patches for Office XP, Word 2003, and
Word Viewer :

http://www.microsoft.com/technet/security/Bulletin/MS09-068.mspx"
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

# Word.
version = get_kb_item("SMB/Office/Word/Version");
if (version)
{
  path = get_kb_item("SMB/Office/Word/ProductPath");
  if (isnull(path)) path = "n/a";

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Word 2003.
  if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8313)
  {
    info = string(
      "  Product           : Word 2003\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 11.0.8313.0\n"
    );
  }
  # Word 2002.
  else if (ver[0] == 10 && ver[1] == 0 && ver[2] < 6856)
  {
    info = string(
      "  Product           : Word 2002\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 10.0.6856.0\n"
    );
  }

  if (info)
  {
    set_kb_item(name:"SMB/Missing/MS09-068", value:TRUE);
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
  if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8313)
  {
    info = string(
      "  Product           : Word Viewer / Word Viewer 2003\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 11.0.8313.0\n"
    );
  }

  if (info)
  {
    set_kb_item(name:"SMB/Missing/MS09-068", value:TRUE);

    hotfix_add_report(info);
    hotfix_security_hole();
    exit(0);
  }
}
