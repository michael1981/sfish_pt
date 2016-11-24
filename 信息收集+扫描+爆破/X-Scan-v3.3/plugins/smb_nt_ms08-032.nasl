#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(33134);
 script_version("$Revision: 1.9 $");

 script_cve_id("CVE-2007-0675", "CVE-2008-0956");
 script_bugtraq_id(29558);
 script_xref(name:"OSVDB", value:"33627");
 script_xref(name:"OSVDB", value:"46062");
 script_xref(name:"OSVDB", value:"46076");
 script_xref(name:"OSVDB", value:"46087");

 name["english"] = "MS08-032: Cumulative Security Update of ActiveX Kill Bits (950760)";

 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
multiple memory corruption vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the sapi.dll ActiveX control. 

The version of this control installed on the remote host reportedly
contains multiple memory corruption flaws.  If an attacker can trick a
user on the affected host into visiting a specially-crafted web page,
he may be able to leverage this issue to execute arbitrary code on the
host subject to the user's privileges." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008 :

http://www.microsoft.com/technet/security/bulletin/ms08-032.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Determines if sapi.dll kill bit is set";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
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
  "{47206204-5eca-11d2-960f-00c04f8ee628}",
  "{3bee4890-4fe9-4a37-8c1e-5e7e12791c1f}",
  "{40F23EB7-B397-4285-8F3C-AACE4FA40309}"
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

  set_kb_item(name:"SMB/Missing/MS08-032", value:TRUE);
}
