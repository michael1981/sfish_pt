#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39783);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2009-1136");
  script_bugtraq_id(35642);
  script_xref(name:"OSVDB", value:"55806");
  script_xref(name:"Secunia", value:"35800");

  script_name(english:"MS09-043: Vulnerabilities in Microsoft Office Web Components Control Could Allow Remote Code Execution (973472)");
  script_summary(english:"Checks kill bits for each affected control");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Windows host contains an ActiveX control that could allow\n",
      "remote code execution."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote Windows host includes Microsoft Office Web Components, a\n",
      "collection of Component Object Model (COM) controls for publishing and\n",
      "viewing spreadsheets, charts, and databases on the web.\n",
      "\n",
      "A privately reported vulnerability in Microsoft Office Web Components\n",
      "reportedly can be abused to corrupt the system state and allow\n",
      "execution of arbitrary code."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.microsoft.com/technet/security/advisory/973472.mspx"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string("
Microsoft has released a set of patches for Office XP and 2003, as 
well as for Microsoft ISA server :

http://www.microsoft.com/technet/security/bulletin/ms09-043.mspx"
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
 
  script_dependencies("smb_hotfixes.nasl", "smb_nt_ms09-043.nasl");
  script_require_keys("SMB/WindowsVersion", "SMB/Missing/MS09-043");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Missing/MS09-043")) exit(0);
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


if (activex_init() != ACX_OK) exit(0);


# Test each control.
info = "";
clsids = make_list(
  "{0002E541-0000-0000-C000-000000000046}",
  "{0002E559-0000-0000-C000-000000000046}"
);

foreach clsid (clsids)
{
  file = activex_get_filename(clsid:clsid);
  if (file)
  {
    if (activex_get_killbit(clsid:clsid) != TRUE)
    {
      version = activex_get_fileversion(clsid:clsid);
      if (!version) version = "Unknown";

      info += string(
        "\n",
        "  Class Identifier : ", clsid, "\n",
        "  Filename         : ", file, "\n",
        "  Version          : ", version, "\n"
      );
      if (!thorough_tests) break;
    }
  }
}
activex_end();


if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 4) s = "s";
    else s = "";

    report = string(
      "\n",
      "The kill-bit has not been set for the following control", s, " :\n",
      "\n",
      info
    );

    if (!thorough_tests)
    {
      report = string(
        report,
        "\n",
        "Note that Nessus did not check whether there were other kill-bits\n",
        "that have not been set because 'Thorough Tests' was not enabled\n",
        "when this scan was run.\n"
      );
    }
    security_hole(port:kb_smb_transport(), extra:report);
  }
  else security_hole(kb_smb_transport());
}
