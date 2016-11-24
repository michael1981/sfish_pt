#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(35634);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2009-0305");
 script_bugtraq_id(33663);
 script_xref(name:"OSVDB", value:"51833");

 script_name(english:"Cumulative Security Update of ActiveX Kill Bits (960715)");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is missing a security update containing
ActiveX kill bits." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing a list of kill bits for ActiveX controls
that are known to contain vulnerabilities. 

If these ActiveX controls are ever installed on the remote host,
either now or in the future, they would expose it to various security
issues." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released an advisory about this :

http://www.microsoft.com/technet/security/advisory/960715.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 script_summary(english:"Determines if the newest kill bits are set");

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 
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
  "{FFBB3F3B-0A5A-4106-BE53-DFE1E2340CB1}",
  "{4788DE08-3552-49EA-AC8C-233DA52523B9}",
  "{1E216240-1B7D-11CF-9D53-00AA003C9CB6}",
  "{3A2B370C-BA0A-11d1-B137-0000F8753F5D}",
  "{B09DE715-87C1-11d1-8BE3-0000F8754DA1}",
  "{cde57a43-8b86-11d0-b3c6-00a0c90aea82}",
  "{6262d3a0-531b-11cf-91f6-c2863c385e30}",
  "{0ECD9B64-23AA-11d0-B351-00A0C9055D8E}",
  "{C932BA85-4374-101B-A56C-00AA003668DC}",
  "{248dd896-bb45-11cf-9abc-0080c7e7b78d}"
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
