#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39350);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2008-0024", "CVE-2008-2475", "CVE-2009-0208");
  script_bugtraq_id(33918, 35218, 35247, 35248);
  script_xref(name:"OSVDB", value:"54968");

  script_name(english:"Cumulative Security Update of ActiveX Kill Bits (969898)");
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
      "Microsoft has released an advisory about this :\n",
      "\n",
      "http://www.microsoft.com/technet/security/advisory/969898.mspx"
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
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
if (hotfix_check_server_core() == 1) exit(0);


if (activex_init() != ACX_OK) exit(0);


# Test each control.
info = "";
clsids = make_list(
  # Microsoft Visual Studio 'MSCOMM32.OCX' ActiveX Control (CVE-2008-0024)
  "{648A5600-2C6E-101B-82B6-000000000014}",
  # Derivco ActiveX Control (BID 35247)
  "{D8089245-3211-40F6-819B-9E5E92CD61A2}",
  # eBay Enhanced Picture Service ActiveX Control (CVE-2008-2475)
  "{4C39376E-FA9D-4349-BACC-D305C1750EF3}",
  "{C3EB1670-84E0-4EDA-B570-0B51AAE81679}",
  # HP Virtual Rooms Client ActiveX Control (CVE-2009-0208)
  "{00000032-9593-4264-8B29-930B3E4EDCCD}"
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
}
