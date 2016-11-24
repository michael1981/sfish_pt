#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39622);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2008-0015");
  script_bugtraq_id(35558);
  script_xref(name:"OSVDB", value:"55651");

  script_name(english:"MS09-032: Cumulative Security Update of ActiveX Kill Bits (973346)");
  script_summary(english:"Checks kill bits for each affected control");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Windows host is missing a security update containing\n",
      "ActiveX kill bits."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is missing a list of kill bits for ActiveX controls\n",
      "that are known to contain vulnerabilities.\n",
      "\n",
      "If these ActiveX controls are ever installed on the remote host,\n",
      "either now or in the future, they would expose it to various security\n",
      "issues."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Windows 2000, XP, 2003,\n",
      "Vista and 2008 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-032.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/07/06"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/07/14"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/07/07"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0, "SMB/Registry/Enumerated KB item is missing.");
if (hotfix_check_server_core() == 1) exit(0, "Windows Server Core installs are not affected.");

if ( hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:3) <= 0 ) exit(0);



if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");


# Test each control.
info = "";
clsids = make_list(
  "{011B3619-FE63-4814-8A84-15A194CE9CE3}",
  "{0149EEDF-D08F-4142-8D73-D23903D21E90}",
  "{0369B4E5-45B6-11D3-B650-00C04F79498E}",
  "{0369B4E6-45B6-11D3-B650-00C04F79498E}",
  "{055CB2D7-2969-45CD-914B-76890722F112}",
  "{0955AC62-BF2E-4CBA-A2B9-A63F772D46CF}",
  "{15D6504A-5494-499C-886C-973C9E53B9F1}",
  "{1BE49F30-0E1B-11D3-9D8E-00C04F72D980}",
  "{1C15D484-911D-11D2-B632-00C04F79498E}",
  "{1DF7D126-4050-47F0-A7CF-4C4CA9241333}",
  "{2C63E4EB-4CEA-41B8-919C-E947EA19A77C}",
  "{334125C0-77E5-11D3-B653-00C04F79498E}",
  "{37B0353C-A4C8-11D2-B634-00C04F79498E}",
  "{37B03543-A4C8-11D2-B634-00C04F79498E}",
  "{37B03544-A4C8-11D2-B634-00C04F79498E}",
  "{418008F3-CF67-4668-9628-10DC52BE1D08}",
  "{4A5869CF-929D-4040-AE03-FCAFC5B9CD42}",
  "{577FAA18-4518-445E-8F70-1473F8CF4BA4}",
  "{59DC47A8-116C-11D3-9D8E-00C04F72D980}",
  "{7F9CB14D-48E4-43B6-9346-1AEBC39C64D3}",
  "{823535A0-0318-11D3-9D8E-00C04F72D980}",
  "{8872FF1B-98FA-4D7A-8D93-C9F1055F85BB}",
  "{8A674B4C-1F63-11D3-B64C-00C04F79498E}",
  "{8A674B4D-1F63-11D3-B64C-00C04F79498E}",
  "{9CD64701-BDF3-4D14-8E03-F12983D86664}",
  "{9E77AAC4-35E5-42A1-BDC2-8F3FF399847C}",
  "{A1A2B1C4-0E3A-11D3-9D8E-00C04F72D980}",
  "{A2E3074E-6C3D-11D3-B653-00C04F79498E}",
  "{A2E30750-6C3D-11D3-B653-00C04F79498E}",
  "{A8DCF3D5-0780-4EF4-8A83-2CFFAACB8ACE}",
  "{AD8E510D-217F-409B-8076-29C5E73B98E8}",
  "{B0EDF163-910A-11D2-B632-00C04F79498E}",
  "{B64016F3-C9A2-4066-96F0-BD9563314726}",
  "{BB530C63-D9DF-4B49-9439-63453962E598}",
  "{C531D9FD-9685-4028-8B68-6E1232079F1E}",
  "{C5702CCC-9B79-11D3-B654-00C04F79498E}",
  "{C5702CCD-9B79-11D3-B654-00C04F79498E}",
  "{C5702CCE-9B79-11D3-B654-00C04F79498E}",
  "{C5702CCF-9B79-11D3-B654-00C04F79498E}",
  "{C5702CD0-9B79-11D3-B654-00C04F79498E}",
  "{C6B14B32-76AA-4A86-A7AC-5C79AAF58DA7}",
  "{CAAFDD83-CEFC-4E3D-BA03-175F17A24F91}",
  "{D02AAC50-027E-11D3-9D8E-00C04F72D980}",
  "{F9769A06-7ACA-4E39-9CFB-97BB35F0E77E}",
  "{FA7C375B-66A7-4280-879D-FD459C84BB02}"
);

foreach clsid (clsids)
{
  if (activex_get_killbit(clsid:clsid) != TRUE)
  {
    info += '  ' + clsid + '\n';
    if (!thorough_tests) break;
  }
}
activex_end();


if (info)
{
  set_kb_item(name:"SMB/Missing/MS09-032", value:TRUE);

  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 1) s = "s";
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

  exit(0);
}
else exit(0, "The host is not affected.");
