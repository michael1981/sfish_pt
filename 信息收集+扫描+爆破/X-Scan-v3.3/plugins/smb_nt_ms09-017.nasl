#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38742);
  script_version("$Revision: 1.5 $");

  script_cve_id(
    "CVE-2009-0220",
    "CVE-2009-0221",
    "CVE-2009-0222",
    "CVE-2009-0223",
    "CVE-2009-0224",
    "CVE-2009-0225",
    "CVE-2009-0226",
    "CVE-2009-0227",
    "CVE-2009-0556",
    "CVE-2009-1128",
    "CVE-2009-1129",
    "CVE-2009-1130",
    "CVE-2009-1131",
    "CVE-2009-1137"
  );
  script_bugtraq_id(
    34351,
    34831,
    34833,
    34834,
    34835,
    34837,
    34839,
    34840,
    34841,
    34876,
    34879,
    34880,
    34881,
    34882
  );
  script_xref(name:"OSVDB", value:"53182");
  script_xref(name:"OSVDB", value:"54381");
  script_xref(name:"OSVDB", value:"54382");
  script_xref(name:"OSVDB", value:"54383");
  script_xref(name:"OSVDB", value:"54384");
  script_xref(name:"OSVDB", value:"54385");
  script_xref(name:"OSVDB", value:"54386");
  script_xref(name:"OSVDB", value:"54387");
  script_xref(name:"OSVDB", value:"54388");
  script_xref(name:"OSVDB", value:"54389");
  script_xref(name:"OSVDB", value:"54390");
  script_xref(name:"OSVDB", value:"54391");
  script_xref(name:"OSVDB", value:"54392");
  script_xref(name:"OSVDB", value:"54393");
  script_xref(name:"OSVDB", value:"54394");

  script_name(english: "MS09-017: Vulnerabilities in Microsoft Office PowerPoint Could Allow Remote Code Execution (967340)");
  script_summary(english:"Checks version of PowerPoint");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "Arbitrary code can be executed on the remote host through Microsoft\n",
      "PowerPoint."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote Windows host is running a version of Microsoft PowerPoint,\n",
      "PowerPoint Viewer, or PowerPoint Converter that is affected by\n",
      "multiple vulnerabilities.  If an attacker can trick a user on the\n",
      "affected host into opening a specially crafted PowerPoint file, he\n",
      "could leverage these issues to execute arbitrary code subject to the\n",
      "user's privileges."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for PowerPoint 2000, 2002,\n",
      "2003, and 2007, PowerPoint Viewer 2003 and 2007, as well as the the\n",
      "Microsoft Office Compatibility Pack :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-017.mspx"
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


# PowerPoint.
info = "";
pp_patched = FALSE;

version = get_kb_item("SMB/Office/PowerPoint/Version");
if (version)
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  path = get_kb_item("SMB/Office/PowerPoint/ProductPath");
  if (isnull(path)) path = "n/a";

  # PowerPoint 2007.
  if (
    ver[0] == 12 && ver[1] == 0 && 
    (
      ver[2] < 6500 ||
      (ver[2] == 6500 && ver[3] < 5000)
    )
  )
  {
    info = string(
      "  Product           : PowerPoint 2007\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 12.0.6500.5000\n"
    );
  }
  # PowerPoint 2003.
  else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8307)
  {
    info = string(
      "  Product           : PowerPoint 2003\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 11.0.8307.0\n"
    );
  }
  # PowerPoint 2002.
  else if (ver[0] == 10 && ver[1] == 0 && ver[2] < 6853)
  {
    info = string(
      "  Product           : PowerPoint 2002\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 10.0.6853.0\n"
    );
  }
  # PowerPoint 2000 - fixed in 9.0.0.8978
  else if (ver[0] == 9 && ver[1] == 0 && ver[2] == 0 && ver[3] < 8978)
  {
    info = string(
      "  Product           : PowerPoint 2000\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 9.0.0.8978\n"
    );
  }

  if (info)
  {
    set_kb_item(name:"SMB/Missing/MS09-017", value:TRUE);
    hotfix_add_report(info);
    hotfix_security_hole();
    exit(0);
  }

  pp_patched = TRUE;
}


# PowerPoint Viewer.
version = get_kb_item("SMB/Office/PowerPointViewer/Version");
if (version && pp_patched == FALSE)
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  path = get_kb_item("SMB/Office/PowerPointViewer/ProductPath");
  if (isnull(path)) path = "n/a";

  # PowerPoint Viewer 2007.
  if (
    ver[0] == 12 && ver[1] == 0 && 
    (
      ver[2] < 6502 ||
      (ver[2] == 6502 && ver[3] < 5000)
    )
  )
  {
    info = string(
      "  Product           : PowerPoint Viewer 2007\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 12.0.6502.5000\n"
    );
  }
  # Office PowerPoint Viewer 2003.
  else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8305)
  {
    info = string(
      "  Product           : Office PowerPoint Viewer 2003\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 11.0.8305.0\n"
    );
  }

  if (info)
  {
    set_kb_item(name:"SMB/Missing/MS09-017", value:TRUE);
    hotfix_add_report(info);
    hotfix_security_hole();
    exit(0);
  }
}


# PowerPoint Converter.
version = get_kb_item("SMB/Office/PowerPointCnv/Version");
if (version)
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  path = get_kb_item("SMB/Office/PowerPointCnv/ProductPath");
  if (isnull(path)) path = "n/a";

  #  PowerPoint 2007 converter.
  if (
    ver[0] == 12 && ver[1] == 0 && 
    (
      ver[2] < 6500 ||
      (ver[2] == 6500 && ver[3] < 5000)
    )
  )
  {
    info = string(
      "  Product           : PowerPoint 2007 Converter\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version, "\n",
      "  Fix               : 12.0.6500.5000\n"
    );
  }

  if (info)
  {
    set_kb_item(name:"SMB/Missing/MS09-017", value:TRUE);
    hotfix_add_report(info);
    hotfix_security_hole();
    exit(0);
  }
}
